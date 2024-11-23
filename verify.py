from keygen import KG
from sign import Signer
import os
import numpy as np
from typing import Tuple
import hashlib
import galois

class Verifier:

    def __init__(self, params: Tuple[int, int, int, int, galois.GF], public_key: np.ndarray, M: bytes, signature: np.ndarray):
        self.params = params
        # self.private_seed = private_seed
        self.r = params[0]
        self.m = params[1]
        self.v = params[2]
        self.SHAKE = params[3]
        self.field = params[4]
        self.n = self.v + self.m

        self.salt = signature[-16:]

        self.Verify(public_key, M, signature)


    def Verify(self, public_key, M, s):
        h = calculate_h(M, self.salt)
        # print(f'h: {h}')
        e = EvaluatePublicMap(public_key, s)


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

    def EvaluatePublicMap(public_key: np.ndarray, s: np.ndarray) -> np.ndarray:
        pass

    