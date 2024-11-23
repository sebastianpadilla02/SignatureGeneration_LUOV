from keygen import KG
from sign import Signer
import os
import numpy as np
from typing import Tuple
import hashlib
import galois

class Verifier:

    def __init__(self, params: Tuple[int, int, int, int, galois.GF], public_key: bytes, M: bytes, signature: np.ndarray):
        self.params = params
        # self.private_seed = private_seed
        self.r = params[0]
        self.m = params[1]
        self.v = params[2]
        self.SHAKE = params[3]
        self.field = params[4]
        self.n = self.v + self.m

        salt = signature[-16:]
        s_bytes = signature[:-16]
        self.s = self.obtain_s(s_bytes)
        public_seed = public_key[:32]
        self.Q2 = public_key[32:]

        # self.Verify(salt, public_seed, M, signature)

    def obtain_s(self, s_bytes: bytes):
        total_bits = self.n * self.r
        # Convertir los bytes de `s` en una cadena binaria
        s_bits = bin(int.from_bytes(s_bytes, byteorder='big'))[2:]  # Eliminar '0b'
        
        s_bits = s_bits[:total_bits]
        # s = np.zeros((self.m, 1), dtype=int)

        # for i in range(self.m):
        #     s[i, 0] = int.from_bytes(s_bytes[i * 2: (i + 1) * 2], 'big')
        print(f's_bits: {s_bits} y su longitud: {len(s_bits)}')

        # Dividir los bits de `s` en elementos individuales
        s = [int(s_bits[i:i + self.r], 2) for i in range(0, total_bits, self.r)]
        return s_bits

    def Verify(self, salt, public_seed, M, s):
        h = self.calculate_h(M, salt)
        # print(f'h: {h}')


        e = self.EvaluatePublicMap(salt, public_seed, s)


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
        len_signature

    