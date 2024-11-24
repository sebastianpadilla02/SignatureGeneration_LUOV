import numpy as np
from typing import Tuple
import hashlib
import galois

class Verifier:

    # Constructor de la clase Verifier, donde se almacenan los parametros y se calculan las matrices necesarias para la verificación
    def __init__(self, params: Tuple[int, int, int, int, galois.GF], public_key: bytes, M: bytes, signature: np.ndarray):
        self.params = params
        # self.private_seed = private_seed
        self.r = params[0]
        self.m = params[1]
        self.v = params[2]
        self.SHAKE = params[3]
        self.field = params[4]
        self.n = self.v + self.m

        #Separar la firma en s y salt
        s, salt = self.obtain_s(signature)

        #Obtener la semilla pública y la matriz Q2 de la llave pública
        public_seed, Q2 = self.obtain_Q2(public_key)

        self.Verify(s, salt, public_seed, Q2, M)

    # Método que separa la firma en s y salt
    def obtain_s(self, signature: bytes) -> Tuple[np.ndarray, bytes]:
        # Separar los últimos 16 bytes de la firma como salt
        salt = signature[-16:]
        s_bytes = signature[:-16]  # Los primeros bytes son `s`

        total_bits = self.n * self.r

        # Calcular cuántos ceros se necesitan para completar el último byte
        cantidad_ceros = 0
        if total_bits % 8 != 0:
            cantidad_ceros = 8 - (total_bits % 8)

        # Convertir los bytes de `s` en una cadena binaria
        s_bits = bin(int.from_bytes(s_bytes, byteorder='big'))[2:].zfill(cantidad_ceros + total_bits)  # Eliminar '0b'

        #Elimina los ultimos ceros que se añadieron para completar el byte
        s_bits = s_bits[:total_bits]

        # Dividir los bits de `s` en elementos individuales
        s = [int(s_bits[i:i + self.r], 2) for i in range(0, total_bits, self.r)]

        s = self.field(s) # Convertir a campo finito

        s = s.reshape(-1, 1) # Convertir a un vector columna

        return s, salt

    # Método que separa la llave pública en la semilla pública y la matriz Q2
    def obtain_Q2(self, public_key: bytes) -> Tuple[bytes, np.ndarray]:
        # Separar la semilla pública y Q2 de la llave pública
        public_seed = public_key[:32]
        Q2_bits = public_key[32:]

        D2 = self.m * (self.m + 1) // 2   #Dimensiones de columna de Q2

        # Convertir Q2_bits a un string binario
        Q2_bit_string = ''.join(f'{byte:08b}' for byte in Q2_bits)

        # Extraer los bits de Q2 y reconstruir la matriz
        Q2 = np.zeros((self.m, D2), dtype=int)
        for j in range(D2):
            for i in range(self.m):
                bit_index = i + j * self.m
                Q2[i, j] = int(Q2_bit_string[bit_index])
        
        return public_seed, Q2

    # Método que verifica la firma   
    def Verify(self, s: np.ndarray, salt: bytes, public_seed: bytes, Q2: np.ndarray, M: bytes) -> None:
        # Calcular h
        h = self.calculate_h(M, salt)

        # Calcular e
        e = self.EvaluatePublicMap(public_seed, Q2, s)

        # Comparar e y h
        self.result = self.Compare(e, h)

    # Método que calcula h
    def calculate_h(self, M: bytes, salt: bytes) -> np.ndarray:
        # Concatenar el mensaje, 0x00 y el salt
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
        num_bytes = (num_bits + 7) // 8  # Convertir a número de bytes redondeando hacia arriba

        hash_output = shake.digest(num_bytes)

        # Convertir el hash en un vector sobre F_{2^r} y almacenar en un array de numpy
        bit_string = ''.join(f'{byte:08b}' for byte in hash_output)  # Convertir los bytes a una cadena de bits

        h = np.zeros((self.m, 1), dtype=int)

        for i in range(self.m):
            # Tomar bloques de `r` bits y convertirlos en enteros
            r_bits = bit_string[i * self.r: (i + 1) * self.r]
            h[i,0] = int(r_bits, 2)

        return h

    # Método que evalúa el mapa público
    def EvaluatePublicMap(self, public_seed: bytes, Q2: np.ndarray, s:np.ndarray) -> np.ndarray:
        # Calcular Q1, C y L
        C, L, Q1 = self.SqueezePublicMap(public_seed)

        # Concatenar Q1 y Q2
        Q = np.hstack((Q1, Q2))

        # Convertir a campo finito
        C = self.field(C)
        L = self.field(L)

        # Calcular e = C + Ls
        e = C + L @ s

        # LLenar la matriz e con los valores de Q y s
        column = 0
        for i in range(self.n):
            print(f'Iteración {i}')
            for j in range(i, self.n):
                for k in range(self.m):
                    e[k] = e[k] + Q[k, column] * s[i] * s[j]
                column += 1

        return e
    
    # Método que de la semilla pública logra llenar las matrices C, L y Q1
    def SqueezePublicMap(self, public_seed: bytes) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        q1_size = self.v * (self.v + 1) // 2 + self.v * self.m

        # Inicializamos las matrices C, L y Q1
        C = np.zeros((self.m, 1), dtype=int)
        L = np.zeros((self.m, self.n), dtype=int)
        Q1 = np.zeros((self.m, q1_size), dtype=int)

        # El número de bytes necesarios para cada bloque de 16 filas
        num_bytes_per_block = 2 * (1 + self.n + (self.v*(self.v+1))//2 + self.v * self.m)

        #LLenado de matrices con bloques de 16 filas 
        for i in range((self.m + 15)//16):
            #LLamada de G para generar los bytes necesarios para cada fila
            G_output = self.G(public_seed, i, num_bytes_per_block)

            # Generar la matriz C
            # Tomar los primeros 2 bytes
            first_2_bytes = G_output[:2]

            # Conversión de los 2 bytes a bits en formato string
            bits = ''.join(f'{byte:08b}' for byte in first_2_bytes)

            # En este condicional se llena la matriz C, si m no es divisible entre 16 y es el ultimo bloque generado entra al if
            if(self.m % 16 != 0) and (i == (self.m + 15)//16 - 1):
                bytes_needed = ((self.m % 16) + 7)//8   # Calcular cuantos bytes quedan faltando para rellenar la fila de la matriz
                bits_added = 0
                pos = 0
                #Si se necesitan 2 bytes, se añade 1 byte entero de manera normal
                if(bytes_needed == 2):
                    for l in range(16*i, 16*i + 8):
                        C[l, 0] = int(bits[bits_added])
                        bits_added += 1
                    
                    pos = l + 1
                else:
                    pos = 16*i

                # Se calcula cuantos bits faltan del byte restante y se toman los bits menos significativos
                bits_restantes = self.m % 16 - bits_added
                bits_menos_significativos = bits[-bits_restantes:]

                # Se añaden los bits a la matriz C
                for h in range(bits_restantes):
                    C[pos, 0] = int(bits_menos_significativos[h])
                    pos += 1
            else:
                bits_added = 0   # Contador de bits añadidos
                # Añadir columna a columna cada bit generado
                for c in range(16*i, 16*i + 16):
                    C[c, 0] = int(bits[bits_added])
                    bits_added += 1
            
            #Generar la matriz L
            # Tomar los siguientes 2n bytes
            bytes_for_L = G_output[2:2 + 2 * self.n]

            # Conversión de los 2n bytes a bits en formato string
            bits_L = ''.join(f'{byte:08b}' for byte in bytes_for_L)

            # En este condicional se llena la matriz L, si m no es divisible entre 16 y es el ultimo bloque generado entra al if
            if(self.m % 16 != 0) and (i == (self.m + 15)//16 - 1):
                bytes_needed = ((self.m % 16) + 7)//8   # Calcular cuantos bytes quedan faltando para rellenar la fila de la matriz
                bits_added = 0
                column = 0

                for cont_bits in range(0, len(bits_L), 16):
                    #Se extraen dos bytes 
                    bits_2_bytes = bits_L[cont_bits:cont_bits+16]

                    bits_added = 0
                    pos = 0
                    #Si se necesitan 2 bytes para completar las filas, se añade un byte normal
                    if(bytes_needed == 2):
                        for l in range(16*i, 16*i + 8):
                            L[l, column] = int(bits_2_bytes[bits_added])
                            bits_added += 1
                        
                        pos = l + 1
                    else:
                        pos = 16*i

                    # Se calculan los bits restantes y se añaden los menos significativos a la matriz
                    bits_restantes = self.m % 16 - bits_added

                    bits_menos_significativos = bits_2_bytes[-bits_added:]

                    for h in range(bits_restantes):
                        L[pos, column] = int(bits_menos_significativos[h])
                        pos += 1

                    column += 1
            else:
                bits_added = 0   # Contador de bits añadidos
                # Añadir columna a columna cada bit generado
                for j in range(self.n):
                    for c in range(16*i, 16*i + 16):
                        L[c, j] = int(bits_L[bits_added])
                        bits_added += 1
            
            #Generar la matriz Q1

            total_bytes_for_Q1 = 2 * ((self.v * (self.v + 1)) // 2 + self.v * self.m)

            #Se obtienen los siguientes 2(v*(v+1)/2 + v*m) bytes
            bytes_for_Q1 = G_output[2 + 2 * self.n:2 + 2 * self.n + total_bytes_for_Q1]

            # Se convierten los bytes a bits en formato string
            bits_Q1 = ''.join(f'{byte:08b}' for byte in bytes_for_Q1)

            # En este condicional se llena la matriz Q1, si m no es divisible entre 16 y es el ultimo bloque generado entra al if
            if(self.m % 16 != 0) and (i == (self.m + 15)//16 - 1):
                bytes_needed = ((self.m % 16) + 7)//8   #Bytes necesarios para llenar la matriz
                bits_added = 0
                column = 0
                for cont_bits in range(0, len(bits_Q1), 16):
                    bits_2_bytes = bits_Q1[cont_bits:cont_bits+16]
                    bits_added = 0
                    pos = 0
                    #Se añade un byte de manera normal si se necesitan 2 bytes
                    if(bytes_needed == 2):
                        for l in range(16*i, 16*i + 8):
                            Q1[l, column] = int(bits_2_bytes[bits_added])
                            bits_added += 1
                        
                        pos = l + 1
                    else:
                        pos = 16*i

                    #Se calculan los bits restantes y se toman los menos significativos de este byte
                    bits_restantes = self.m % 16 - bits_added

                    bits_menos_significativos = bits_2_bytes[-bits_added:]

                    for h in range(bits_restantes):
                        Q1[pos, column] = int(bits_menos_significativos[h])
                        pos += 1

                    column += 1
            else:
                #Contador de bytes añadidos
                bits_added = 0
                #Se añaden columna a columna los bits
                for j in range ((self.v * (self.v + 1)) // 2 + self.v * self.m):
                    for c in range(16*i, 16*i + 16):
                        Q1[c, j] = int(bits_Q1[bits_added])
                        bits_added += 1

        return C, L, Q1

    # Funcion G(SHAKE 128) que toma la semilla pública, el indice del bloque de 16 filas y el numero de bytes necesarios a generar
    def G(self, public_seed: bytes, index: int, num_bytes: int) -> bytes:
        # Concatenar el public_seed con el índice
        seed_with_index = public_seed + bytes([index])

        # Inicializar SHAKE128
        shake = hashlib.shake_128()

        #Absorver la concatenacion entre semilla pública e índice
        shake.update(seed_with_index)

        # Generar el número de bytes necesario
        return shake.digest(num_bytes)    
    
    # Comparación entre los vectores e y h lo que verifica la firma
    def Compare(self, e: np.ndarray, h: np.ndarray) -> bool:
        if np.array_equal(e, h):
            return True
        else:
            return False