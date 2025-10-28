# Sistema de Votación Segura

**Descripción**
Proyecto en Python que implementa un sistema de votación sencillo y seguro usando:
- SQLite para almacenamiento local (`datos/votacion.db`).
- Hash de contraseñas con PBKDF2-HMAC-SHA256 (archivo `usuarios.py`).
- Cifrado de votos con AES‑GCM (archivo `votos.py`) y clave almacenada en `datos/clave_aes.key`.
- Interfaz de consola en `main.py` para registro, inicio de sesión y voto.

---

## Estructura de archivos
```
/ (repositorio)
├─ main.py            # Punto de entrada (menú de consola)
├─ db.py              # Conexión y creación de tablas SQLite (datos/votacion.db)
├─ usuarios.py        # Registro y autenticación de usuarios (PBKDF2)
├─ votos.py           # Cifrado, almacenamiento y descifrado de votos (AES-GCM)
├─ datos/             # Carpeta creada en tiempo de ejecución (DB, logs, clave)
│  ├─ votacion.db
│  ├─ clave_aes.key
│  └─ app.log
```

---

## Requisitos
- Python 3.8+
- Paquete `cryptography`
- Visualizador de bases de datos (Ejemplo en VSCode: SQLite Viewer)

Hemos incluido un `requirements.txt` para instalar dependencias (instalación abajo).

---

## Instalación (requirements.txt)
```bash
# clona el repositorio o descarga los archivos en una carpeta local
python3 -m venv venv
source venv/bin/activate    # en Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Uso
1. Ejecuta el script principal:
```bash
python main.py
```

2. En el menú podrás elegir:
- **1. Registrar usuario**: registra nombre, email y contraseña (la contraseña se valida: 8+ caracteres, mayúscula, minúscula y número).
- **2. Iniciar sesión y votar**: iniciar sesión; si ya tienes un voto puedes verlo o cambiarlo. Los votos se cifran con AES-GCM antes de guardarlos.
- **3. Salir**: termina la aplicación.

El flujo guarda trazas en `datos/app.log` y la base de datos en `datos/votacion.db`.

---

## Desarrollo y pruebas
- Para probar cifrado/descifrado: registra un usuario, introduce un voto, luego elige ver voto para comprobar que `descifrar_voto` funciona correctamente.
- Revisa `datos/app.log` para trazabilidad de eventos durante pruebas.

---

## Autores
- Autores: Pablo Pino Castillo y Alejandro Ros Quesada.