import cupy as cp
import time

# Crear un array grande en la GPU
print("Creando matriz grande en la GPU...")
start = time.time()
a = cp.random.random((10000, 10000))
b = cp.random.random((10000, 10000))
result = cp.dot(a, b)  # Producto punto en GPU
cp.cuda.Device(0).synchronize()  # Sincronizar para medir tiempo correctamente
end = time.time()

print(f"Tiempo de cálculo en la GPU: {end - start:.2f} segundos")
