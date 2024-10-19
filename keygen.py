import hashlib
import numpy as np
from typing import Tuple

class KG:

    #Constructor de la clase, donde se almacena cada parametro(r, m, v, SHAKE, n)
    def __init__(self, params: list, private_seed: bytes):
        self.r = params[0]
        self.m = params[1]
        self.v = params[2]
        self.SHAKE = params[3]
        self.n = self.v + self.m
        self.KeyGen(private_seed)
        self.public_key

    #Método KeyGen que genera la llave pública
    def KeyGen(self, private_seed: bytes):
        #Generación de la función hashing H(SHAKE 128 o 256)
        private_sponge = self.InitializeAndAbsorb(private_seed)

        #Generación de la semilla publica y la matriz T a partir de la esponja privada
        public_seed, T = self.SqueezeT(private_sponge)

        #Generación de las 3 matrices C(parte constante), L(parte lineal), Q1(parte cuadrática) a partir de la semilla pública
        C, L, Q1 = self.SqueezePublicMap(public_seed)

        #Encontrar Q2 que sirve para obtener la llave pública, a partir de Q1 y T
        Q2 = self.FindQ2(Q1, T)

        #Se encuentra la llave publica
        self.public_key = self.FindPublicKey(Q2, public_seed)

    #Función que inicializa el SHAKE y absorve la semilla privada
    def InitializeAndAbsorb(self, seed: bytes) -> hashlib:
        #Inicializar el shake según el parámetro
        if(self.SHAKE == 128):
            shake = hashlib.shake_128()
        else:
            shake = hashlib.shake_256()
        
        #Absorve la semilla privada
        shake.update(seed)

        return shake

    #Función que de una esponja privada exprime valores necesarios para la semilla publica y la matriz T
    def SqueezeT(self, private_sponge: hashlib) -> Tuple[bytes, np.ndarray]:
        #Inicializar la matriz T de dimensiones v x m
        T = np.zeros((self.v, self.m), dtype = int)

        # Calcular el número de bytes necesarios para generar una matriz de v x m bits
        num_bytes = ((self.m + 7) // 8) * self.v  # Redondear al mayor(función techo) para asegurarse de tener suficientes bits
        
        # Exprimir los bytes necesarios(32 para la semilla privada y num_bytes para la matriz T)
        random_bytes = private_sponge.digest(32 + num_bytes)  

        # Separa los primeros 32 bytes para la semilla pública
        public_seed = random_bytes[:32]  

        # Los bytes restantes son para la matriz T
        random_bytes_for_T = random_bytes[32:]

        # Extraemos los bits correspondientes a cada fila de la matriz T y recorremos la matriz por filas
        for i in range(self.v):
            start_byte_index = i * ((self.m + 7) // 8)  # Inicio del rango de bytes para la fila i
            end_byte_index = (i + 1) * ((self.m + 7) // 8)  # Final del rango de bytes para la fila i

            byte_chunk = random_bytes_for_T[start_byte_index:end_byte_index]  # Obtener los bytes correspondientes
        
            # Tomar todos los bytes excepto el último
            all_but_last = byte_chunk[:-1]

            # Tomar el último byte
            last_byte = bytes([byte_chunk[-1]])

            bits = ''.join(f'{byte:08b}' for byte in all_but_last)  # Convertir los bytes a bits en formato str

            # Encontrar los bits que faltan para llenar la fila y tomar los menos significativos del ultimo byte
            bits_faltantes = self.m % 8
            last_byte_bits = '' + f'{last_byte[0]:08b}'
            if bits_faltantes > 0:
                last_byte_bits = last_byte_bits[-bits_faltantes:]

            # Concatenar los bits del ultimo byte al resto de bits para tener la fila completa
            bits += last_byte_bits
            
            # Asignar los primeros bits a la fila i de la matriz T
            for j in range(self.m):
                T[i, j] = int(bits[j])  # Asignar el bit correspondiente
            
        return public_seed, T

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
                        C[l, 0] = bits[bits_added]
                        bits_added += 1
                    
                    pos = l + 1

                # Se calcula cuantos bits faltan del byte restante y se toman los bits menos significativos
                bits_restantes = self.m % 16 - bits_added
                bits_menos_significativos = bits[-bits_restantes:]

                # Se añaden los bits a la matriz C
                for h in range(bits_restantes):
                    C[pos, 0] = bits_menos_significativos[h]
                    pos += 1
            else:
                bits_added = 0   # Contador de bits añadidos
                # Añadir columna a columna cada bit generado
                for c in range(16*i, 16*i + 16):
                    C[c, 0] = bits[bits_added]
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
                            L[l, column] = bits_2_bytes[bits_added]
                            bits_added += 1
                        
                        pos = l + 1

                    # Se calculan los bits restantes y se añaden los menos significativos a la matriz
                    bits_restantes = self.m % 16 - bits_added

                    bits_menos_significativos = bits_2_bytes[-bits_added:]

                    for h in range(bits_restantes):
                        L[pos, column] = bits_menos_significativos[h]
                        pos += 1

                    column += 1
            else:
                bits_added = 0   # Contador de bits añadidos
                # Añadir columna a columna cada bit generado
                for j in range(self.n):
                    for c in range(16*i, 16*i + 16):
                        L[c, j] = bits_L[bits_added]
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
                            Q1[l, column] = bits_2_bytes[bits_added]
                            bits_added += 1
                        
                        pos = l + 1

                    #Se calculan los bits restantes y se toman los menos significativos de este byte
                    bits_restantes = self.m % 16 - bits_added

                    bits_menos_significativos = bits_2_bytes[-bits_added:]

                    for h in range(bits_restantes):
                        Q1[pos, column] = bits_menos_significativos[h]
                        pos += 1

                    column += 1
            else:
                #Contador de bytes añadidos
                bits_added = 0
                #Se añaden columna a columna los bits
                for j in range ((self.v * (self.v + 1)) // 2 + self.v * self.m):
                    for c in range(16*i, 16*i + 16):
                        Q1[c, j] = bits_Q1[bits_added]
                        bits_added += 1
        
        return C, L, Q1

    #Encontrar Pk1
    def findPk1(self, k: int, Q1: np.ndarray) -> np.ndarray:
        Pk_1 = np.zeros((self.v, self.v), dtype = int)
        column = 0
        for i in range(self.v):
            for j in range(i, self.v):
                Pk_1[i,j] = Q1[k, column]
                column += 1
            column = column + self.m

        return Pk_1

    #Encontrar Pk2
    def findPk2(self, k: int, Q1: np.ndarray) -> np.ndarray:
        Pk_2 = np.zeros((self.v, self.m), dtype = int)
        column = 0
        for i in range(self.v):
            column = column + self.v - i
            for j in range(self.m):
                Pk_2[i,j] = Q1[k, column]
                column += 1
        
        return Pk_2

    #Función para encontrar Q2
    def FindQ2(self, Q1: np.ndarray, T: np.ndarray) -> np.ndarray:
        D2 = self.m * (self.m + 1) // 2 #Dimension de columnas de Q2

        #Inicializacion de Q2
        Q2 = np.zeros((self.m,D2), dtype = int)

        #Se llena la matriz Q2 tal cual como en el documento, se hacen las operaciones modulo 2 ya que estamos en F2
        for k in range(self.m):
            Pk_1 = self.findPk1(k, Q1)
            Pk_2 = self.findPk2(k, Q1)
            term1 = -np.dot(T.T, np.dot(Pk_1, T)) % 2
            term2 = np.dot(T.T, Pk_2) %2
            Pk_3 = (term1 + term2) % 2

            column = 0
            for i in range(self.m):
                Q2[k, column] = Pk_3[i, i]
                column += 1
                for j in range(i+1, self.m):
                    Q2[k, column] = (Pk_3[i, j] + Pk_3[j, i]) % 2 
                    column += 1
        
        return Q2
    
    def bits_to_bytes(self, bit_string: str) -> bytes:
        # Convertir el string de bits a un entero
        byte_value = int(bit_string, 2)

        # Convertir el entero a bytes
        num_bytes = len(bit_string) // 8
        byte_array = byte_value.to_bytes(num_bytes, byteorder='big')

        return byte_array

    #Función para generar la llave publica
    def FindPublicKey(self, Q2: np.ndarray, public_seed: bytes) -> bytes :
        D2 = self.m * (self.m + 1) // 2   #Dimensiones de columna de Q2
        concat_bits = ''
        
        #Se recorre Q2 columna por columna y se va concatenando cada 1 y 0
        for j in range(D2):
            for i in range(self.m):
                concat_bits += str(Q2[i, j])

        # Si la longitud de los bits no es múltiplo de 8, tenemos bits sobrantes, estos bits se completan con ceros para formar el ultimo byte
        if len(concat_bits) % 8 > 0:
            while (len(concat_bits) % 8 != 0):
                concat_bits += '0'

        #Se convierte los bytes de la llave publica a bits en formato string
        public_seed_bits = ''.join(f'{byte:08b}' for byte in public_seed)
        
        #Se concatena la semilla publica con los bits de Q2 traducidos y se convierten a bytes
        pk = self.bits_to_bytes(public_seed_bits + concat_bits)
        
        return pk

