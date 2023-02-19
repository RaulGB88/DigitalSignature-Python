from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from pathlib import Path

def fichero_hash_sha256(file):
    """La función retorna el código HASH con SHA256 del fichero"""

    # Creamos el objeto HASH usando el algoritmo SHA256
    h = SHA256.new()

    # Abrimos el fichero en modo binario (rb)
    linea = 0
    while linea != b'':
        # Leemos cada vez 1024 bytes. linea contiene lo leido
        linea = file.read(1024)
        #Acumulamos los datos en objeto hash y lo actualizamos
        h.update(linea)
    # Devuelve el HASH final tras haber leído todo el fichero
    return h

def main():
    #Pedir la clave publica del usuario
    fichero_path = Path(__file__).parent / "publica_usuario_A.pem"
    public_key = RSA.import_key(open(fichero_path).read()) #leemos la clave publica del usuario_A

    #Abro el fichero fichero firmado que me han enviado.
    filename = input("Nombre de fichero: ") #Leemos el fichero a firmar
    fichero_path = Path(__file__).parent / filename
    fichero = open(fichero_path,'rb')
    # Obtengo el su Hash usando el mismo algoritmo.
    codigoHASH = fichero_hash_sha256(fichero)
    fichero.close()
    
    #Abrimos un fichero que contiene la signatura
    fichero_path = Path(__file__).parent / "SignaturaFichero.txt"
    fichero = open(fichero_path,'rb')
    signature = SHA256.new(fichero.read())

    #signature = RSA.import_key(open(fichero_path).read())
    #enc_session_key = fichero.read(signature.size_in_bytes())

    fichero.close()
    cipher_rsa = PKCS1_PSS.new(public_key)

    try:
        
        cipher_rsa.verify(codigoHASH, signature) #Compara el Hash que obtiene con el Hash que le pasamos para verificar que los datos no se han modificado
        print("The signature is valid.")

    except (ValueError, TypeError):
        print("The signature is not valid.")


if __name__=="__main__":
    main()