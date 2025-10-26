import os
import logging
from usuarios import registrar_usuario, autenticar_usuario
from votos import almacenar_voto, descifrar_voto, obtener_voto, actualizar_voto
from db import crear_tablas

os.makedirs("datos", exist_ok=True)
crear_tablas()

# Asegura que la clave AES exista antes de cualquier voto
try:
    generar_clave()
except Exception as e:
    print("Error al generar la clave AES:", e)

# CONFIGURACIÓN DE LOGGING
logging.basicConfig(
    filename="datos/app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def main():
    print("===================================")
    print("🗳️  SISTEMA DE VOTACIÓN SEGURA  🗳️")
    print("===================================")

    while True:
        print("\nMenú principal:")
        print("1. Registrar usuario")
        print("2. Iniciar sesión y votar")
        print("3. Salir")

        opcion = input("> ").strip()

        # Validación de opción
        if opcion not in ("1", "2", "3"):
            print("Opción no válida. Por favor, elige 1, 2 o 3.")
            logging.warning(f"Opción inválida introducida en menú: {opcion}")
            continue

        try:
            if opcion == "1":
                nombre = input("Nombre: ").strip()
                email = input("Email: ").strip()
                password = input("Contraseña: ").strip()
                registrar_usuario(nombre, email, password)

            elif opcion == "2":
                email = input("Email: ").strip()
                password = input("Contraseña: ").strip()
                usuario_id = autenticar_usuario(email, password)

                if usuario_id:
                    voto_existente = obtener_voto(usuario_id)
                    if voto_existente:
                        print("Ya tienes un voto registrado.")
                        print("1. Ver voto")
                        print("2. Cambiar voto")
                        print("3. Cancelar")
                        subopcion = input("> ").strip()
                        
                        if subopcion == "1":
                            voto_cifrado, nonce, aad = voto_existente
                            voto_desc = descifrar_voto(voto_cifrado, nonce, aad)
                            print(f"Tu voto actual es: {voto_desc}")
                        elif subopcion == "2":
                            nuevo_voto = input("Introduce tu nuevo voto: ").strip()
                            actualizar_voto(usuario_id, nuevo_voto)
                            print("Voto actualizado correctamente.")
                        else:
                            print("Operación cancelada.")
                    else:
                        voto = input("Introduce tu voto: ").strip()
                        almacenar_voto(usuario_id, voto)
                        print("Voto cifrado y registrado correctamente.")
            elif opcion == "3":
                print("Gracias por usar el Sistema de Votación Segura.")
                logging.info("Aplicación finalizada por el usuario.")
                break

        except KeyboardInterrupt:
            print("\n Programa interrumpido por el usuario.")
            logging.warning("Ejecución interrumpida manualmente (Ctrl+C).")
            break

        except Exception as e:
            print("Ha ocurrido un error inesperado.")
            logging.error("Error inesperado: %s", str(e))

# ----------------------------------------
# EJECUCIÓN DIRECTA
# ----------------------------------------
if __name__ == "__main__":
    main()