from keygen import KG
import os
import numpy as np
from typing import Tuple
import hashlib
import galois

class Signer:
    def __init__(self, params: list, private_seed: bytes, M: bytes) -> None:
        self.params = params
        # self.private_seed = private_seed
        self.r = params[0]
        self.m = params[1]
        self.v = params[2]
        self.SHAKE = params[3]
        self.field = params[4]
        
        # Reutilizamos la clase KG para derivar la semilla pública y T
        self.keygen = KG(params, private_seed)

        self.s = None
        self.salt = None

        self.Sign(private_seed, M)

    def Sign(self, private_seed: bytes, M: bytes) -> None:
        public_seed, T = self.derive_public_seed_and_T(private_seed)
        # print(f'public seed: {public_seed}')
        # print(f'T: {T}')

        C, L, Q1 = self.G(public_seed)

        salt = os.urandom(16)

        # print(f'salt: {salt} y su longitud: {len(salt)}')

        h = self.calculate_h(M, salt)
        # print(f'h: {h}')

        solution_found = False
        s_prime = None
        cont = 0

        while not solution_found:
            cont += 1
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

            # print(f'A: {A} y su tamaño: {A.shape} y tipo: {type(A)}')

            # print(f'cont: {cont}')

            # Resolver el sistema lineal A[:, :-1] * x = A[:, -1] usando eliminación gaussiana

            # Extraer la submatriz de coeficientes y el vector de soluciones

            coef_matrix = A[:, :-1]  # Matriz de coeficientes

            # print(f'coef_matrix: {coef_matrix} y su tamaño: {coef_matrix.shape} y tipo: {type(coef_matrix)}') 

            solution_vector = A[:, -1]  # Vector de soluciones 

            # print(f'solution_vector: {solution_vector} y su tamaño: {solution_vector.shape} y tipo: {type(solution_vector)}')

            try:
                # Resolver el sistema para `o`
                o = np.linalg.solve(coef_matrix, solution_vector)  

                # o = self.field(o)
                # o = np.linalg.solve(coef_matrix, solution_vector) % mod_value

                # Verificar si `o` es una solución válida

                is_solution = np.all((coef_matrix @ o) == (solution_vector))

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

        # print(f's_prime: {s_prime} y su tamaño: {s_prime.shape} y tipo: {type(s_prime)}')
        # print(f'coefs: {coef_matrix}')
        # print(f'solution: {solution_vector}')

        # print(f'o: {o}')
        # print(f's_prime: {s_prime}')


        # Construir el vector de firma `s` como se especifica en el algoritmo
        s = self.build_signature(T, v, o, s_prime)

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

        # print(f'RHS: {RHS.shape}')
        # print(f'LHS: {LHS.shape}')
        h, C, L, v, T = self.field(h), self.field(C), self.field(L), self.field(v), self.field(T)

        for k in range(self.m):
            # Paso 4: Calcular P_{k,1} y P_{k,2}
            Pk_1 = self.keygen.findPk1(k, Q1)  # Función que debe devolver una matriz (v, v)
            Pk_2 = self.keygen.findPk2(k, Q1)  # Función que debe devolver una matriz (v, m)

            Pk_1 = self.field(Pk_1)
            Pk_2 = self.field(Pk_2)

            # Paso 6: Actualizar RHS[k] con v^T * P_{k,1} * v
            RHS[k] = (RHS[k] - v.T @ Pk_1 @ v) # Resta cuadrática en variables de vinagre

            # Paso 7: Calcular F_{k,2} como -(P_{k,1} + P_{k,1}^T)T + P_{k,2}
            Fk_2 = (-(Pk_1 + Pk_1.T) @ T + Pk_2)

            # Paso 8: Actualizar LHS[k] con v^T * F_{k,2}
            LHS[k] = (LHS[k] + v @ Fk_2)  # Términos bilineales en vinagre y aceite

        # Paso 4: Concatenar LHS y RHS
        augmented_matrix = np.hstack((LHS, RHS))

        augmented_matrix = self.field(augmented_matrix)

        # print(f'augmented matrix: {augmented_matrix} y su tamaño: {augmented_matrix.shape} y tipo: {type(augmented_matrix)}') 

        # print(f'RHS: {RHS}')

        # print(f'Augmented matrix: {augmented_matrix.shape}')

        return augmented_matrix

    def calculate_RHS(self, h, C, L, v):
        # print(f'c: {C.shape}')
        # print(f'l: {L.shape}')
        # # print(f'q1: {Q1.shape}')
        # # print(f't: {T.shape}')
        # print(f'h: {h.shape}')
        # print(f'v: {v.shape}')

        # field = self.irreducible_polynomial

        # print(f'L: {L} y su tamaño: {L.shape} y tipo: {type(L)}')

        # Concatenar `v` con un vector de ceros de tamaño `m`
        v_padded = self.field(np.vstack((v.reshape(-1, 1), np.zeros((self.m, 1), dtype=int))))

        # print(f'v_padded: {v_padded} y su tamaño: {v_padded.shape} y tipo: {type(v_padded)}')
     
        # Transponer `v_padded` para hacer `(v || 0)^T`
        v_padded_T = v_padded.T

        # print(f'v_padded_T: {v_padded_T} y su tamaño: {v_padded_T.shape} y tipo: {type(v_padded_T)}')

        L = self.field(L)
        
        # Calcular L(v||0)^T
        Lv = L.dot(v_padded_T.T)

        # print(f'Lv: {Lv} y su tamaño: {Lv.shape} y tipo: {type(Lv)}')

        h = self.field(h)
        C = self.field(C)



        # Calcular RHS = h - C - L(v||0)^T
        RHS = h - C - Lv

        # print(f'RHS: {RHS.shape}')

        # Aplicar operación módulo 2^r para mantener los valores en F_{2^r}
        # RHS = RHS % mod_value 
        # print(f'RHS: {RHS} y type: {type(RHS)}')
        return RHS
    
    def calculate_LHS(self, L, T):
        # Negar la matriz `T`
        L = self.field(L)
        T  = self.field(T)
        # np.set_printoptions(threshold=np.inf)
        # print(f'L: {L} y su tamaño: {L.shape} y tipo: {type(L)}')
        # T = self.field(T)
        # print(f'T: {T} y su tamaño: {T.shape} y tipo: {type(T)}')

        T_neg = -T  # Aplicamos módulo 2^r para mantener los valores en F_{2^r}

        # Crear la matriz identidad `1_m`
        identity_m = np.eye(self.m, dtype=int)

        # Concatenar `-T` y `1_m` verticalmente para formar una matriz de tamaño (v + m, m)
        concat_matrix = np.vstack((T_neg, identity_m))
        # print(f'concat_matrix: {concat_matrix} y su tamaño: {concat_matrix.shape} y tipo: {type(concat_matrix)}')

        # concat_matrix = self.field(concat_matrix)

        # Calcular L(-T || 1_m)
        LHS = (L.dot(concat_matrix))  # Resultado en el campo F_{2^r}
        #np.set_printoptions(threshold=np.inf)
        #print(f'LHS: {LHS} tamaño: {LHS.shape} y tipo: {type(LHS)}')
        return LHS
    
    def build_signature(self, T, v, o, s_prime) -> np.ndarray:
        # Construir la matriz de bloques
        # Matriz identidad de tamaño `v x v`
        T = self.field(T)
        v = self.field(v)
        o = self.field(o)

        identity_v = np.eye(len(v), dtype=int)
        identity_v = self.field(identity_v)

        # Matriz identidad de tamaño `m x m`
        identity_m = np.eye(len(o), dtype=int)
        identity_m = self.field(identity_m)

        # Concatenar las matrices para formar el bloque
        # `1_v` y `-T`
        top_block = np.hstack((identity_v, -T))

        # `0` y `1_m`
        bottom_block = np.hstack((np.zeros((len(o), len(v)), dtype=int), identity_m))

        # Crear la matriz completa
        block_matrix = np.vstack((top_block, bottom_block))

        # Multiplicar por `s_prime` y aplicar el módulo
        s = (block_matrix @ s_prime)

        # print(f's: {s} y su tamaño: {s.shape} y tipo: {type(s)}')

        return s
    
    def encode_signature(self):

        # Calcular el número de bytes necesarios para cada elemento en F_{2^r}
        num_bytes = (self.r + 7) // 8  # Redondear hacia arriba para obtener el número de bytes
        
        # Codificar cada elemento en `s` en `num_bytes` bytes
        encoded_elements = bytearray()
        for element in self.s:
            # Reducir el elemento módulo el polinomio irreducible
            element = int(element[0])
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

    # def reduce_vector(self, vector, irreducible_poly):
    #     return np.array([self.reduce_mod_irreducible(element, irreducible_poly) for element in vector])
    
    # def reduce_matrix(self, matrix, irreducible_poly):
    #     return np.array([self.reduce_vector(row, irreducible_poly) for row in matrix])

    # def reduce_mod_irreducible(self, value, irreducible_poly):
    #     value = int(value)
    #     while value.bit_length() >= irreducible_poly.bit_length():
    #         print(f'entré')
    #         shift = value.bit_length() - irreducible_poly.bit_length()
    #         value ^= irreducible_poly << shift

    #     return value