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

        self.Sign(private_seed, M)

    def Sign(self, private_seed: bytes, M: bytes) -> None:
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

            break



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

        h = np.zeros(self.m, dtype=int)

        for i in range(self.m):
            # Tomar bloques de `r` bits y convertirlos en enteros
            r_bits = bit_string[i * self.r: (i + 1) * self.r]
            # print(f'r_bits: {r_bits} y su longitud: {len(r_bits)}')
            h[i] = int(r_bits, 2)

        return h
    
    def BuildAugmentedMatrix(self, C, L, Q1, T, h, v):
        # print(f'c: {C.shape}')
        # print(f'l: {L.shape}')
        # print(f'q1: {Q1.shape}')
        # print(f't: {T.shape}')
        # print(f'h: {h.shape}')
        # print(f'v: {v.shape}')
        



