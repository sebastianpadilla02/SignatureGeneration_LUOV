from keygen import KG
import os
import numpy as np
from typing import Tuple
import hashlib

class Signer:
    def __init__(self, params: list, private_seed: bytes, M: bytes) -> None:
        self.params = params
        # self.private_seed = private_seed
        self.r = params[0]
        self.m = params[1]
        self.v = params[2]
        self.SHAKE = params[3]
        
        # Reutilizamos la clase KG para derivar la semilla pública y T
        self.keygen = KG(params, private_seed)

        self.s = None
        self.salt = None

        self.Sign(private_seed, M)

    def Sign(self, private_seed: bytes, M: bytes) -> None:
        mod_value = 2 ** self.r  # Definir el módulo para F_{2^r}
        public_seed, T = self.derive_public_seed_and_T(private_seed)
        # print(f'public seed: {public_seed}')
        # print(f'T: {T}')

        C, L, Q1 = self.G(public_seed)

        # print(f'C: {C}')
        # print(f'L: {L}')
        # print(f'Q1: {Q1}')

        salt = os.urandom(16)

        # print(f'salt: {salt} y su longitud: {len(salt)}')

        h = self.calculate_h(M, salt)
        # print(f'h: {h}')

        solution_found = False
        s_prime = None

        while not solution_found:
            num_bits = self.r * self.v
            num_bytes = (num_bits + 7) // 8  # Convertir a número de bytes redondeando hacia arriba

            # Generar v aleatorio de tamaño rv/8 bytes
            v_bytes = os.urandom(num_bytes)

            # Convertir el hash en un vector sobre F_{2^r} y almacenar en un array de numpy
            bit_string = ''.join(f'{byte:08b}' for byte in v_bytes)  # Convertir los bytes a una cadena de bits

            # print(f'bit_string: {bit_string} y su longitud: {len(bit_string)}')

            v = np.zeros(self.v, dtype=int)

            for i in range(self.v):
                # Tomar bloques de `r` bits y convertirlos en enteros
                r_bits = bit_string[i * self.r: (i + 1) * self.r]
                # print(f'r_bits: {r_bits} y su longitud: {len(r_bits)}')
                v[i] = int(r_bits, 2)

            # print(f'v: {v}')
            A = self.BuildAugmentedMatrix(C, L, Q1, T, h, v)

            # Resolver el sistema lineal A[:, :-1] * x = A[:, -1] usando eliminación gaussiana

            # Extraer la submatriz de coeficientes y el vector de soluciones
            coef_matrix = A[:, :-1] % mod_value
            solution_vector = A[:, -1] % mod_value

            try:
                # Resolver el sistema para `o`
                o = self.gauss_jordan_modular(coef_matrix, solution_vector, mod_value)
                # o = np.linalg.solve(coef_matrix, solution_vector) % mod_value

                # Verificar si `o` es una solución válida
                is_solution = np.all((coef_matrix @ o % mod_value) == (solution_vector % mod_value))

                if is_solution:
                    # Si se encontró una solución única, construir `s'`
                    s_prime = np.concatenate((v, o)).reshape(-1, 1)
                    solution_found = True
                else:
                    # Si `o` no es una solución válida, intentar con otro `v`
                    continue
            except ValueError as e:
                # Si no se encontró una solución, intentar con otro `v`
                continue


        print(f'coefs: {coef_matrix}')
        print(f'solution: {solution_vector}')

        # print(f'o: {o}')
        # print(f's_prime: {s_prime}')


        # Construir el vector de firma `s` como se especifica en el algoritmo
        s = self.build_signature(T, v, o, mod_value, s_prime)

        self.salt = salt
        self.s = s


    def derive_public_seed_and_T(self, private_seed) -> Tuple[bytes, np.ndarray]:
        # Llama al método SqueezeT para derivar `public_seed` y `T` a partir de la private_seed
        public_seed, T = self.keygen.SqueezeT(self.keygen.InitializeAndAbsorb(private_seed))
        
        # Devuelve la `public_seed` y la matriz `T`
        return public_seed, T
    
    def G(self, public_seed):
        # Llama a SqueezePublicMap de la clase KG para obtener C, L, y Q1
        C, L, Q1 = self.keygen.SqueezePublicMap(public_seed)
        return C, L, Q1
    
    def calculate_h(self, M: bytes, salt: bytes) -> np.ndarray:
        # Línea 4: Concatenar el mensaje, 0x00 y el salt
        concatenated_message = M + b'\x00' + salt

        # Llama a la función H de la clase KG para calcular h
        #Inicializar el shake según el parámetro
        if(self.SHAKE == 128):
            shake = hashlib.shake_128()
        else:
            shake = hashlib.shake_256()
        
        # Absorber el mensaje concatenado en la esponja
        shake.update(concatenated_message)

        # Generar `m * r` bits de salida
        num_bits = self.m * self.r
        # print(f'num_bits: {num_bits}')
        num_bytes = (num_bits + 7) // 8  # Convertir a número de bytes redondeando hacia arriba

        hash_output = shake.digest(num_bytes)

        # Convertir el hash en un vector sobre F_{2^r} y almacenar en un array de numpy
        bit_string = ''.join(f'{byte:08b}' for byte in hash_output)  # Convertir los bytes a una cadena de bits

        # print(f'bit_string: {bit_string} y su longitud: {len(bit_string)}')

        h = np.zeros((self.m, 1), dtype=int)

        for i in range(self.m):
            # Tomar bloques de `r` bits y convertirlos en enteros
            r_bits = bit_string[i * self.r: (i + 1) * self.r]
            # print(f'r_bits: {r_bits} y su longitud: {len(r_bits)}')
            h[i,0] = int(r_bits, 2)

        return h
    
    def BuildAugmentedMatrix(self, C, L, Q1, T, h, v):
        # print(f'c: {C.shape}')
        # print(f'l: {L.shape}')
        # print(f'q1: {Q1.shape}')
        # print(f't: {T.shape}')
        # print(f'h: {h.shape}')
        # print(f'v: {v.shape}')

        RHS = self.calculate_RHS(h, C, L, v)

        LHS = self.calculate_LHS(L, T)

        mod_value = 2 ** self.r  # Definir el módulo para F_{2^r}

        for k in range(self.m):
            # Paso 4: Calcular P_{k,1} y P_{k,2}
            Pk_1 = self.keygen.findPk1(k, Q1)  # Función que debe devolver una matriz (v, v)
            Pk_2 = self.keygen.findPk2(k, Q1)  # Función que debe devolver una matriz (v, m)

            # Paso 6: Actualizar RHS[k] con v^T * P_{k,1} * v
            RHS[k] = (RHS[k] - v.T @ Pk_1 @ v) % mod_value  # Resta cuadrática en variables de vinagre

            # Paso 7: Calcular F_{k,2} como -(P_{k,1} + P_{k,1}^T)T + P_{k,2}
            Fk_2 = (-(Pk_1 + Pk_1.T) @ T + Pk_2) % mod_value

            # Paso 8: Actualizar LHS[k] con v^T * F_{k,2}
            LHS[k] = (LHS[k] + v @ Fk_2) % mod_value  # Términos bilineales en vinagre y aceite

        # Paso 4: Concatenar LHS y RHS
        augmented_matrix = np.hstack((LHS, RHS))

        # print(f'Augmented matrix: {augmented_matrix.shape}')

        return augmented_matrix

    def calculate_RHS(self, h, C, L, v):
        # print(f'c: {C.shape}')
        # print(f'l: {L.shape}')
        # # print(f'q1: {Q1.shape}')
        # # print(f't: {T.shape}')
        # print(f'h: {h.shape}')
        # print(f'v: {v.shape}')

        # Concatenar `v` con un vector de ceros de tamaño `m`
        v_padded = np.vstack((v.reshape(-1, 1), np.zeros((self.m, 1), dtype=int)))
        
        # Transponer `v_padded` para hacer `(v || 0)^T`
        v_padded_T = v_padded.T
        
        # Calcular L(v||0)^T
        Lv = L.dot(v_padded_T.T)

        mod_value = 2 ** self.r
        Lv = Lv % mod_value

        # Calcular RHS = h - C - L(v||0)^T
        RHS = h - C - Lv

        # print(f'RHS: {RHS.shape}')

        # Aplicar operación módulo 2^r para mantener los valores en F_{2^r}
        RHS = RHS % mod_value 

        return RHS
    
    def calculate_LHS(self, L, T):
        # Negar la matriz `T`
        T_neg = -T % (2 ** self.r)  # Aplicamos módulo 2^r para mantener los valores en F_{2^r}

        # Crear la matriz identidad `1_m`
        identity_m = np.eye(self.m, dtype=int)

        # Concatenar `-T` y `1_m` verticalmente para formar una matriz de tamaño (v + m, m)
        concat_matrix = np.vstack((T_neg, identity_m))

        # Multiplicar L por la matriz concatenada y aplicar módulo 2^r
        mod_value = 2 ** self.r
        LHS = (L.dot(concat_matrix)) % mod_value  # Resultado en el campo F_{2^r}

        # print(f'LHS: {LHS} tamaño: {LHS.shape}')
        return LHS
    
    def gauss_jordan_modular(self, A, b, mod_value):
        """
        Resolver el sistema de ecuaciones Ax = b usando eliminación Gaussiana en módulo `mod_value`.
        
        Parámetros:
        A -- matriz de coeficientes (entera)
        b -- vector de soluciones (entero)
        mod_value -- valor del módulo (2^r en tu caso)
        
        Retorna:
        x -- solución entera en el campo F_{mod_value} si el sistema tiene solución única.
        """
        # Concatenar A y b en una matriz aumentada
        A = A % mod_value
        b = b % mod_value
        augmented_matrix = np.hstack((A, b.reshape(-1, 1)))  # Matriz aumentada (A|b)
        
        rows, cols = augmented_matrix.shape
        
        # Eliminación Gaussiana
        for i in range(rows):
            # Buscar el primer elemento no nulo en la columna i (pivote)
            pivot = augmented_matrix[i, i]
            
            # Verificar si el pivot es cero o no tiene inverso modular
            if pivot == 0 or np.gcd(int(pivot), mod_value) != 1:
                # Buscar otra fila para intercambiar
                found = False
                for j in range(i + 1, rows):
                    if augmented_matrix[j, i] != 0 and np.gcd(int(augmented_matrix[j, i]), mod_value) == 1:
                        augmented_matrix[[i, j]] = augmented_matrix[[j, i]]
                        pivot = augmented_matrix[i, i]
                        found = True
                        break
                # Si no se encontró un pivote invertible, el sistema puede ser singular
                if not found:
                    raise ValueError("No se encontró un pivote invertible; el sistema puede ser singular.")
            
            # Asegurarse de que el pivote sea 1 multiplicándolo por su inverso modular
            pivot_inv = pow(int(pivot), -1, mod_value)
            augmented_matrix[i] = (augmented_matrix[i] * pivot_inv) % mod_value
            
            # Eliminar las entradas en otras filas
            for j in range(rows):
                if j != i:
                    factor = augmented_matrix[j, i]
                    augmented_matrix[j] = (augmented_matrix[j] - factor * augmented_matrix[i]) % mod_value
        
        # Extraer la solución
        x = augmented_matrix[:, -1]
        return x
    
    def build_signature(self, T, v, o, mod_value, s_prime) -> np.ndarray:
        # Construir la matriz de bloques
        # Matriz identidad de tamaño `v x v`
        identity_v = np.eye(len(v), dtype=int)

        # Matriz identidad de tamaño `m x m`
        identity_m = np.eye(len(o), dtype=int)

        # Concatenar las matrices para formar el bloque
        # `1_v` y `-T`
        top_block = np.hstack((identity_v, -T % mod_value))

        # `0` y `1_m`
        bottom_block = np.hstack((np.zeros((len(o), len(v)), dtype=int), identity_m))

        # Crear la matriz completa
        block_matrix = np.vstack((top_block, bottom_block))

        # Multiplicar por `s_prime` y aplicar el módulo
        s = (block_matrix @ s_prime) % mod_value

        return s
    
    def encode_signature(self):
        """
        Codifica la firma `s` y la concatena con el `salt`.

        Parámetros:
        - s: np.array con los elementos de la firma en F_{2^r}
        - salt: bytes, el valor de `salt` de 16 bytes
        - r: int, el tamaño de cada elemento en bits (e.g., 27, 247, 261, 279)

        Retorna:
        - Un bytearray que representa la firma codificada y el salt concatenado.
        """
        # Calcular el número de bytes necesarios para cada elemento en F_{2^r}
        num_bytes = (self.r + 7) // 8  # Redondear hacia arriba para obtener el número de bytes
        
        # Codificar cada elemento en `s` en `num_bytes` bytes
        encoded_elements = bytearray()
        for element in self.s:
            encoded_bytes = int(element).to_bytes(num_bytes, byteorder='big')
            encoded_elements.extend(encoded_bytes)
        
        # Calcular el número total de bits y verificar si es múltiplo de 8
        total_bits = len(self.s) * self.r
        if total_bits % 8 != 0:
            padding_bits = 8 - (total_bits % 8)
            encoded_elements.extend(b'\x00' * (padding_bits // 8))  # Añadir los bytes de padding
        
        # Añadir el `salt` al final
        encoded_elements.extend(self.salt)

        return bytes(encoded_elements)
