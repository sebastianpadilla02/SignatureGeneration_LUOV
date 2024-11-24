# Implementación del Esquema de Firma LUOV

Este proyecto implementa el esquema de firma digital LUOV (Lifted Unbalanced Oil and Vinegar), que incluye la generación de claves, la generación de firmas digitales y la verificación de firmas. LUOV es un protocolo criptográfico basado en ecuaciones cuadráticas multivariables, diseñado como una solución eficiente y segura para la criptografía post-cuántica.

---

## **Características**
- **Generación de claves**: Generación de claves privadas y públicas para firmar y verificar mensajes.
- **Generación de firmas**: Creación de firmas digitales para mensajes utilizando la clave privada.
- **Verificación de firmas**: Verificación de la autenticidad de un mensaje firmado utilizando la clave pública.

---

## **Requisitos**
Esta implementación está escrita en Python y requiere los siguientes módulos:

- [**NumPy**](https://numpy.org/) (para la manipulación de matrices y vectores)
- [**Galois**](https://github.com/mhostetter/galois) (para operaciones en campos finitos)
- [**Hashlib**](https://docs.python.org/3/library/hashlib.html) (para el cálculo de hashes criptográficos)
- [**OS**](https://docs.python.org/3/library/os.html) (para operaciones con el sistema de archivos)
- [**Typing**](https://docs.python.org/3/library/typing.html) (para anotaciones de tipos)

Asegúrate de que los módulos necesarios estén instalados en tu entorno de Python. Puedes instalarlos con los siguientes comandos:

```bash
pip install numpy
pip install galois
```

## **Cómo Funciona**
1. **Generación de claves**:
   - Se genera una clave privada con valores aleatorios.
   - A partir de la clave privada se deriva una clave pública, que incluye un conjunto de ecuaciones cuadráticas definidas sobre un campo finito.

2. **Generación de firmas**:
   - Se calcula un hash del mensaje a firmar.
   - Utilizando la clave privada, el hash se firma resolviendo las ecuaciones cuadráticas asociadas con la clave pública.

3. **Verificación de firmas**:
   - El verificador utiliza la clave pública para calcular el resultado de las ecuaciones cuadráticas con la firma proporcionada.
   - El resultado calculado se compara con el hash del mensaje original.

---

## **Estructura del Proyecto**
- `keygen.py`: Maneja la generación de claves privadas y públicas.
- `sign.py`: Implementa el proceso de creación de firmas.
- `verify.py`: Contiene la lógica para verificar firmas digitales.
- `main.py`: Script de ejemplo que muestra cómo utilizar la implementación.

---

## **Limitaciones**
- Esta implementación está diseñada para fines educativos y puede no estar optimizada para uso en producción.
- Asegúrate de que los parámetros utilizados cumplan con las especificaciones de LUOV para garantizar la seguridad.

---

## **Autores**

* Sebastian Arteta Padilla

* German Centanaro Oviedo

* Luis Espinel Luna

## Criptografía

## Universidad del norte - 2024-30

## Septiembre 2024
