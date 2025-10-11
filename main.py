from usuarios import registrar_usuario, autenticar_usuario
from votos import almacenar_voto, descifrar_voto 

def main():
    print("=== Sistema de Votación Segura ===")
    while True:
        print("\n1. Registrar usuario\n2. Iniciar sesión\n3. Salir")
        opcion = input("> ")
        if opcion == "1":
            nombre = input("Nombre: ")
            email = input("Email: ")
            password = input("Contraseña: ")
            registrar_usuario(nombre, email, password)
        elif opcion == "2":
            email = input("Email: ")
            password = input("Contraseña: ")
            usuario_id = autenticar_usuario(email, password)
            if usuario_id: #Devuelve usaurio si es y None si no es
                voto = input("Introduce tu voto: ")
                #Aqui iria lo de la firma algo tipo: firma = firmar_voto(voto) 
                almacenar_voto(usuario_id, voto)
                print("Voto cifrado y firmado.")
        else:
            break