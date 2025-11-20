import os
import logging
from usuarios import registrar_usuario, autenticar_usuario
from votos import almacenar_voto, descifrar_voto, obtener_voto, actualizar_voto, compartir_voto, ver_votos_compartidos
from db import crear_tablas

os.makedirs("datos", exist_ok=True)
crear_tablas()

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

    # Variables de sesión: Aquí guardaremos las llaves mientras el usuario esté dentro
    usuario_id = None
    usuario_priv_key = None 
    usuario_pub_key = None

    try:
        while True:
            # ----- MODO USUARIO LOGEADO -----
            if usuario_id is not None:
                print(f"\nSesión del usuario {usuario_id}") # !! Aquí igual podríamos poner el nombre u otra cosa
                print("1. Ver/Actualizar mi voto")
                print("2. Compartir mi voto")
                print("3. Ver mis votos compartidos")
                print("4. Cerrar sesión")
                print("5. Salir")

                opcion = input("> ").strip()

                if opcion == "1":
                    voto_data = obtener_voto(usuario_id)
                    
                    if voto_data:
                        print("\nOPCIONES:")
                        print("1. Leer mi voto")
                        print("2. Cambiar mi voto")
                        subopcion = input("> ").strip()
                        
                        if subopcion == "1":
                            # Usamos la clave PRIVADA para leer
                            texto = descifrar_voto(voto_data, usuario_priv_key)
                            print(f"Tu voto secreto es: {texto}")
                            
                        elif subopcion == "2":
                            nuevo_voto = input("Nuevo voto: ").strip()
                            # Usamos la clave PÚBLICA para guardar el nuevo
                            actualizar_voto(usuario_id, nuevo_voto, usuario_pub_key)
                        else:
                            print("Opción no válida. Por favor, elige 1 o 2")
                            continue
                    else:
                        voto = input("Aún no has votado. Introduce tu voto: ").strip()
                        # Usamos la clave PÚBLICA para guardar
                        almacenar_voto(usuario_id, voto, usuario_pub_key)
                
                elif opcion == "2":
                    email_destino = input("Email del usuario con quien compartir: ").strip()
                    compartir_voto(usuario_id, email_destino, usuario_priv_key)

                elif opcion == "3":
                    ver_votos_compartidos(usuario_id, usuario_priv_key)

                elif opcion == "4":
                    # Borramos las claves de la memoria
                    usuario_id = None
                    usuario_priv_key = None
                    usuario_pub_key = None
                    print("Sesión cerrada.")
                    
                elif opcion == "5":
                    break

                else:
                    print("Opción no válida. Por favor, elige 1, 2 o 3")
                    continue

            # ----- MODO INICIO - MENÚ PRINCIPAL -----
            else:
                print("\nMenú principal:")
                print("1. Registrar usuario")
                print("2. Iniciar sesión")
                print("3. Salir")
                opcion = input("> ").strip()

                if opcion == "1":
                    nombre = input("Nombre: ").strip()
                    email = input("Email: ").strip()
                    password = input("Contraseña: ").strip()
                    registrar_usuario(nombre, email, password)

                elif opcion == "2":
                    email = input("Email: ").strip()
                    password = input("Contraseña: ").strip()
                    result = autenticar_usuario(email, password)

                    if result:
                        usuario_id, usuario_priv_key, usuario_pub_key = result
                        print("✅ ¡Bienvenido! Has entrado en el sistema.")
                
                elif opcion == "3":
                    print("Gracias por usar el Sistema de Votación Segura.")
                    logging.info("Aplicación finalizada por el usuario.")
                    break

                else:
                    print("Opción no válida. Por favor, elige 1, 2 o 3.")
                    logging.warning(f"Opción inválida introducida en menú: {opcion}")
                    continue

    except KeyboardInterrupt:
        print("\n Programa interrumpido por el usuario.")
        logging.warning("Ejecución interrumpida manualmente (Ctrl+C).")

    except Exception as e:
        print("Ha ocurrido un error inesperado.")
        logging.error("Error inesperado: %s", str(e))

# ----------------------------------------
# EJECUCIÓN DIRECTA
# ----------------------------------------
if __name__ == "__main__":
    main()