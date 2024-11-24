from keygen import KG
import os
import numpy as np
from typing import Tuple
import hashlib

class Signer:

    #Constructor de la clase, donde se almacena cada parametro(r, m, v, SHAKE, n y el campo) y se llama a la función Sign
    def __init__(self, params: list, private_seed: bytes, M: bytes) -> None:
        self.params = params
        # self.private_seed = private_seed
        self.r = params[0]
        self.m = params[1]
        self.v = params[2]
        self.SHAKE = params[3]
        self.field = params[4]
        self.n = self.v + self.m
        
        # Reutilizamos la clase KG para derivar la semilla pública y T
        self.keygen = KG(params, private_seed)

        self.s = None
        self.salt = None

        self.Sign(private_seed, M)

    #Función Sign, donde se llama a las funciones necesarias para la firma
    def Sign(self, private_seed: bytes, M: bytes) -> None:
        # Generación de la semilla publica y la matriz T a partir de la semilla privada
        public_seed, T = self.derive_public_seed_and_T(private_seed)

        #Generación de las 3 matrices C(parte constante), L(parte lineal), Q1(parte cuadrática) a partir de la semilla pública
        C, L, Q1 = self.G(public_seed)

        #Generación de una salt aleatoria de 16 bytes
        salt = os.urandom(16)

        #Calculo de h a partir del mensaje y la salt
        h = self.calculate_h(M, salt)

        solution_found = False
        s_prime = None
        cont = 0
        # Bucle principal para encontrar una solución válida al sistema de ecuaciones
        while not solution_found:
            cont += 1
            num_bits = self.r * self.v
            num_bytes = (num_bits + 7) // 8  # Convertir a número de bytes redondeando hacia arriba

            # Generar v aleatorio de tamaño rv/8 bytes
            v_bytes = os.urandom(num_bytes)

            # Convertir el hash en un vector sobre F_{2^r} y almacenar en un array de numpy
            bit_string = ''.join(f'{byte:08b}' for byte in v_bytes)  # Convertir los bytes a una cadena de bits

            v = np.zeros(self.v, dtype=int)

            for i in range(self.v):
                # Tomar bloques de `r` bits y convertirlos en enteros
                r_bits = bit_string[i * self.r: (i + 1) * self.r]
                v[i] = int(r_bits, 2)

            # Construir la matriz aumentada `A`
            A = self.BuildAugmentedMatrix(C, L, Q1, T, h, v)

            # Extraer la submatriz de coeficientes y el vector de soluciones

            coef_matrix = A[:, :-1]  # Matriz de coeficientes

            solution_vector = A[:, -1]  # Vector de soluciones 

            try:
                # Resolver el sistema para `o`
                o = np.linalg.solve(coef_matrix, solution_vector)  

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

        # Construir el vector de firma `s` como se especifica en el algoritmo
        s = self.build_signature(T, v, o, s_prime)

        self.salt = salt
        self.s = s

    #Función para derivar la semilla pública y la matriz T a partir de la semilla privada
    def derive_public_seed_and_T(self, private_seed) -> Tuple[bytes, np.ndarray]:
        # Llama al método SqueezeT para derivar `public_seed` y `T` a partir de la private_seed
        public_seed, T = self.keygen.SqueezeT(self.keygen.InitializeAndAbsorb(private_seed))
        
        # Devuelve la `public_seed` y la matriz `T`
        return public_seed, T
    
    #Función para generar las 3 matrices C, L y Q1 a partir de la semilla pública
    def G(self, public_seed: bytes) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        # Llama a SqueezePublicMap de la clase KG para obtener C, L, y Q1
        C, L, Q1 = self.keygen.SqueezePublicMap(public_seed)
        return C, L, Q1
    
    #Función para calcular h a partir del mensaje y la salt
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
            h[i,0] = int(r_bits, 2)

        return h
    
    #Función para construir la matriz aumentada A
    def BuildAugmentedMatrix(self, C: np.ndarray, L: np.ndarray, Q1: np.ndarray, T: np.ndarray, h: np.ndarray, v: np.ndarray) -> np.ndarray:

        # Inicializar los vectores RHS y LHS
        RHS = self.calculate_RHS(h, C, L, v)
        LHS = self.calculate_LHS(L, T)

        #Convertir a campo finito
        h, C, L, v, T = self.field(h), self.field(C), self.field(L), self.field(v), self.field(T)

        #Recorrer cada fila de la matriz aumentada
        for k in range(self.m):
            # Calcular P_{k,1} y P_{k,2}
            Pk_1 = self.keygen.findPk1(k, Q1)  # Función que debe devolver una matriz (v, v)
            Pk_2 = self.keygen.findPk2(k, Q1)  # Función que debe devolver una matriz (v, m)

            # Convertir a campo finito
            Pk_1 = self.field(Pk_1)
            Pk_2 = self.field(Pk_2)

            # Actualizar RHS[k] con v^T * P_{k,1} * v
            RHS[k] = (RHS[k] - v.T @ Pk_1 @ v) # Resta cuadrática en variables de vinagre

            # Calcular F_{k,2} como -(P_{k,1} + P_{k,1}^T)T + P_{k,2}
            Fk_2 = (-(Pk_1 + Pk_1.T) @ T + Pk_2)

            # Actualizar LHS[k] con v^T * F_{k,2}
            LHS[k] = (LHS[k] + v @ Fk_2)  # Términos bilineales en vinagre y aceite

        # Paso 4: Concatenar LHS y RHS
        augmented_matrix = np.hstack((LHS, RHS))

        # Convertir a campo finito
        augmented_matrix = self.field(augmented_matrix)

        return augmented_matrix

    #Función para calcular el RHS(Lado derecho de la ecuación)
    def calculate_RHS(self, h: np.ndarray, C: np.ndarray, L: np.ndarray, v:np.ndarray) -> np.ndarray:

        # Concatenar `v` con un vector de ceros de tamaño `m`
        v_padded = self.field(np.vstack((v.reshape(-1, 1), np.zeros((self.m, 1), dtype=int))))
     
        # Transponer `v_padded` para hacer `(v || 0)^T`
        v_padded_T = v_padded.T

        # Convertir a campo finito
        L = self.field(L)
        
        # Calcular L(v||0)^T
        Lv = L.dot(v_padded_T.T)

        # Convertir a campo finito
        h = self.field(h)
        C = self.field(C)

        # Calcular RHS = h - C - L(v||0)^T
        RHS = h - C - Lv

        return RHS
    
    #Función para calcular el LHS(Lado izquierdo de la ecuación)
    def calculate_LHS(self, L: np.ndarray, T: np.ndarray) -> np.ndarray:
        # Convertir a campo finito
        L = self.field(L)
        T  = self.field(T)

        T_neg = -T  # Negar la matriz `T`

        # Crear la matriz identidad `1_m`
        identity_m = np.eye(self.m, dtype=int)

        # Concatenar `-T` y `1_m` verticalmente para formar una matriz de tamaño (v + m, m)
        concat_matrix = np.vstack((T_neg, identity_m))

        # Calcular L(-T || 1_m)
        LHS = (L.dot(concat_matrix))  # Resultado en el campo F_{2^r}

        return LHS
    
    #Función para construir la firma
    def build_signature(self, T: np.ndarray, v: np.ndarray, o: np.ndarray, s_prime: np.ndarray) -> np.ndarray:

        T = self.field(T)
        v = self.field(v)
        o = self.field(o)

        # Matriz identidad de tamaño `v x v` y convertir a campo finito
        identity_v = np.eye(len(v), dtype=int)
        identity_v = self.field(identity_v)

        # Matriz identidad de tamaño `m x m` y convertir a campo finito
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

        return s
    
    #Función para codificar la firma
    def encode_signature(self) -> bytes:

        # Codificar cada elemento en `s` en `num_bytes` bytes
        encoded_sign = ""
        for element in self.s:
            element = int(element[0])
            num = f"{element:0{self.r}b}"
            encoded_sign += num

        # Calcular el número total de bits y verificar si es múltiplo de 8
        total_bits = self.n * self.r
        if total_bits % 8 != 0:
            for i in range(8 - (total_bits % 8)):
                encoded_sign += "0"

        num_bytes = (len(encoded_sign) + 7) // 8

        # Concatenar el `salt` al final
        encoded_sign = int(encoded_sign, 2).to_bytes(num_bytes, byteorder='big')
        encoded_sign = encoded_sign + self.salt  # Convierte encoded_sign a bytes y concatena

        return bytes(encoded_sign)