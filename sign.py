from keygen import KG
import os

class Signer:
    def __init__(self, params, private_seed):
        self.params = params
        self.private_seed = private_seed
        self.r = params[0]
        self.m = params[1]
        self.v = params[2]
        
        # Reutilizamos la clase KG para derivar la semilla pública y T
        self.keygen = KG(params, private_seed)

    def derive_public_seed_and_T(self):
        # Llama al método SqueezeT para derivar `public_seed` y `T` a partir de la private_seed
        public_seed, T = self.keygen.SqueezeT(self.keygen.InitializeAndAbsorb(self.private_seed))
        
        # Devuelve la `public_seed` y la matriz `T`
        return public_seed, T

# Ejemplo de uso
if __name__ == "__main__":
    # Ejemplo de parámetros y generación de semilla privada
    params = [7, 57, 197, 128]
    private_seed = os.urandom(32)

    # Crear instancia de Signer
    signer = Signer(params, private_seed)

    # Derivar `public_seed` y `T`
    public_seed, T = signer.derive_public_seed_and_T()
    print(f"Public Seed: {public_seed}")
    print(f"T: {T}")
