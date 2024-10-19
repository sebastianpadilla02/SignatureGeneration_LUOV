import os

from keygen import KG

def lectura_params():
    op = 0

    # Valida que se ingrese una opción correcta entre las 6 posibles par definir los parámetros del esquema LUOV
    while op < 1 or op > 6:
        op = int(input("Ingrese el número del nivel de seguridad que quiere implmentar en su llave\n \t1. LUOV-7-57-197 \n \t2. LUOV-7-83-283\n \t3. LUOV-7-110-374 \n \t4. LUOV-47-42-182 \n \t5. LUOV-61-60-261 \n \t6. LUOV-79-76-341\nIngresa la opción: "))
        if(op < 1 and op > 6):
            print('Ingrese una opción válida')

    #Asignación de parámetros
    #params = [r, m, v, SHAKE]
    if op == 1:
        params = [7, 57, 197, 128]
    elif op == 2:
        params = [7, 83, 283, 256]
    elif op == 3:
        params = [7, 110, 374, 256]
    elif op == 4:
        params = [47, 42, 182, 128]
    elif op == 5:
        params = [61, 60, 261, 256]
    elif op == 6:
        params = [79, 76, 341, 256]

    return params, op

# Función que genera la semilla privada de 32 bytes de manera aleatoria
def generar_semilla_privada():
    private_seed = os.urandom(32)
    return private_seed

if __name__ == "__main__":
    #Se leen los parámetros y op para generar los archivos de las llaves.
    params, op = lectura_params()

    #Generación de semilla privada necesaria para la generación de todo en el criptosistema.
    private_seed = generar_semilla_privada()

    #LLamada a la clase KG donde estan almacenados todos los métodos para generar las llaves
    llaves = KG(params, private_seed)

    #Se guardan en variables la llave publica y provada respectivamente
    public_key, private_key = llaves.public_key, private_seed

    print(f'public key: {public_key}')
    print(f'private key: {private_key}')

    #Se hace para definir el nombre del archivo binario donde se guardarán las llaves
    if(op == 1):
        publica = 'public_key_LUOV-7-57-197.bin'
        privada = 'private_key_LUOV-7-57-197.bin'
    elif(op == 2):
        publica = 'public_key_LUOV-7-83-283.bin'
        privada = 'private_key_LUOV-7-83-283.bin'
    elif op == 3:
        publica = 'public_key_LUOV-7-110-374.bin'
        privada = 'private_key_LUOV-7-110-374.bin'
    elif op == 4:
        publica = 'public_key_LUOV-47-42-182.bin'
        privada = 'private_key_LUOV-47-42-182.bin'
    elif op == 5:
        publica = 'public_key_LUOV-61-60-261.bin'
        privada = 'private_key_LUOV-61-60-261.bin'
    elif op == 6:
        publica = 'public_key_LUOV-79-76-341.bin'
        privada = 'private_key_LUOV-79-76-341.bin'

    # Abrir el archivo en la carpeta 'keys' en modo binario
    publica = os.path.join('keys', publica)

    #Se crean loas archivos y se almacenan los bytes de cada semilla en su respectivo archivo
    with open(publica, 'wb') as file:
        file.write(public_key)

    privada = os.path.join('keys', privada)

    with open(privada, 'wb') as file:
        file.write(private_key)
    
