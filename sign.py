import cupy as cp
import os
from keygen import KG
from typing import Tuple
import hashlib


class Signer:
    def __init__(self, params: list, private_seed: bytes, M: bytes) -> None:
        self.params = params
        self.r = params[0]
        self.m = params[1]
        self.v = params[2]
        self.SHAKE = params[3]
        self.irreducible_polynomial = params[4]

        # Reutilizamos la clase KG para derivar la semilla pública y T
        self.keygen = KG(params, private_seed)
        self.s = None
        self.salt = None

        self.Sign(private_seed, M)

    def Sign(self, private_seed: bytes, M: bytes) -> None:
        public_seed, T = self.derive_public_seed_and_T(private_seed)
        C, L, Q1 = self.G(public_seed)
        salt = os.urandom(16)
        h = self.calculate_h(M, salt)

        solution_found = False
        cont = 0

        while not solution_found:
            cont += 1
            v = self.generate_random_vector(self.v, self.r)
            A = self.BuildAugmentedMatrix(C, L, Q1, T, h, v)
            coef_matrix = A[:, :-1]
            solution_vector = A[:, -1]

            try:
                o = self.gauss_jordan_modular(A)
                if cp.all(self.reduce_mod_irreducible(coef_matrix @ o) == self.reduce_mod_irreducible(solution_vector)):
                    solution_found = True
                    s_prime = cp.concatenate((v, o)).reshape(-1, 1)
            except ValueError:
                continue

        self.s = self.build_signature(T, v, o, s_prime)
        self.salt = salt

    def derive_public_seed_and_T(self, private_seed: bytes) -> Tuple[bytes, cp.ndarray]:
        public_seed, T = self.keygen.SqueezeT(self.keygen.InitializeAndAbsorb(private_seed))
        return public_seed, cp.array(T)

    def G(self, public_seed: bytes) -> Tuple[cp.ndarray, cp.ndarray, cp.ndarray]:
        C, L, Q1 = self.keygen.SqueezePublicMap(public_seed)
        return cp.array(C), cp.array(L), cp.array(Q1)

    def calculate_h(self, M: bytes, salt: bytes) -> cp.ndarray:
        concatenated_message = M + b'\x00' + salt
        shake = hashlib.shake_128() if self.SHAKE == 128 else hashlib.shake_256()
        shake.update(concatenated_message)
        num_bits = self.m * self.r
        hash_output = shake.digest((num_bits + 7) // 8)

        bit_string = ''.join(f'{byte:08b}' for byte in hash_output)
        h = cp.array([int(bit_string[i * self.r: (i + 1) * self.r], 2) for i in range(self.m)]).reshape(-1, 1)
        return h

    def generate_random_vector(self, size: int, r: int) -> cp.ndarray:
        num_bits = size * r
        num_bytes = (num_bits + 7) // 8
        v_bytes = os.urandom(num_bytes)
        bit_string = ''.join(f'{byte:08b}' for byte in v_bytes)
        return cp.array([int(bit_string[i * r: (i + 1) * r], 2) for i in range(size)])

    def BuildAugmentedMatrix(self, C, L, Q1, T, h, v):
        RHS = self.calculate_RHS(h, C, L, v)
        LHS = self.calculate_LHS(L, T)

        for k in range(self.m):
            Pk_1 = cp.array(self.keygen.findPk1(k, Q1))
            Pk_2 = cp.array(self.keygen.findPk2(k, Q1))
            RHS[k] = self.reduce_mod_irreducible(RHS[k] - v.T @ Pk_1 @ v)
            Fk_2 = self.reduce_mod_irreducible(-(Pk_1 + Pk_1.T) @ T + Pk_2)
            LHS[k] = self.reduce_mod_irreducible(LHS[k] + v @ Fk_2)

        return cp.hstack((LHS, RHS))

    def calculate_RHS(self, h, C, L, v):
        v_padded = cp.vstack((v.reshape(-1, 1), cp.zeros((self.m, 1), dtype=cp.int32)))
        Lv = L @ v_padded
        return self.reduce_mod_irreducible(h - C - Lv)

    def calculate_LHS(self, L, T):
        identity_m = cp.eye(self.m, dtype=cp.int32)
        concat_matrix = cp.vstack((-T, identity_m))
        return self.reduce_mod_irreducible(L @ concat_matrix)

    def gauss_jordan_modular(self, augmented_matrix):
        rows, cols = augmented_matrix.shape
        for i in range(rows):
            pivot = augmented_matrix[i, i]
            if pivot == 0:
                for j in range(i + 1, rows):
                    if augmented_matrix[j, i] != 0:
                        augmented_matrix[[i, j]] = augmented_matrix[[j, i]]
                        pivot = augmented_matrix[i, i]
                        break
                else:
                    raise ValueError("No se encontró un pivote invertible.")

            pivot_inv = self.reduce_mod_irreducible(pow(int(pivot), -1, self.irreducible_polynomial))
            augmented_matrix[i] = self.reduce_mod_irreducible(augmented_matrix[i] * pivot_inv)

            for j in range(rows):
                if j != i:
                    factor = augmented_matrix[j, i]
                    augmented_matrix[j] = self.reduce_mod_irreducible(augmented_matrix[j] - factor * augmented_matrix[i])

        return augmented_matrix[:, -1]

    def build_signature(self, T, v, o, s_prime):
        identity_v = cp.eye(len(v), dtype=cp.int32)
        identity_m = cp.eye(len(o), dtype=cp.int32)
        top_block = cp.hstack((identity_v, -T))
        bottom_block = cp.hstack((cp.zeros((len(o), len(v)), dtype=cp.int32), identity_m))
        block_matrix = cp.vstack((top_block, bottom_block))
        return self.reduce_mod_irreducible(block_matrix @ s_prime)

    def reduce_mod_irreducible(self, value):
        if isinstance(value, cp.ndarray):
            # Crear un kernel que utilice una variable local para evitar el error de lvalue
            vectorized_reduce = cp.ElementwiseKernel(
                'Q x, Q p',  # Entradas: valor (x) y polinomio irreducible (p), Q indica uint64_t en CUDA
                'Q y',       # Salida: valor reducido (y)
                '''
                Q temp = x;  // Crear una variable local
                while (temp >= (1ULL << (64 - __clzll(p)))) {
                    int shift = __clzll(temp) - __clzll(p);
                    temp ^= p << shift;
                }
                y = temp;
                ''',  # Código CUDA en C++
                'reduce_mod_kernel'
            )
            return vectorized_reduce(value, self.irreducible_polynomial)
        else:
            return self.reduce_mod_scalar(value)

    def reduce_mod_scalar(self, value):
        while value.bit_length() >= self.irreducible_polynomial.bit_length():
            shift = value.bit_length() - self.irreducible_polynomial.bit_length()
            value ^= self.irreducible_polynomial << shift
        return value
