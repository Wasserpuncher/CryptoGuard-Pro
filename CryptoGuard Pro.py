from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import hashlib
import os

class CryptoToolset:
    @staticmethod
    def generate_rsa_key_pair():
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    @staticmethod
    def rsa_encrypt(public_key, plaintext):
        public_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(plaintext.encode())
        return base64.b64encode(ciphertext).decode()

    @staticmethod
    def rsa_decrypt(private_key, ciphertext):
        private_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(private_key)
        ciphertext = base64.b64decode(ciphertext)
        plaintext = cipher.decrypt(ciphertext).decode()
        return plaintext

    @staticmethod
    def generate_aes_key():
        return get_random_bytes(16)

    @staticmethod
    def aes_encrypt(key, plaintext):
        padding = 16 - (len(plaintext) % 16)
        plaintext += chr(padding) * padding

        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(plaintext.encode())
        return base64.b64encode(iv + ciphertext).decode()

    @staticmethod
    def aes_decrypt(key, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext).decode()
        padding = ord(plaintext[-1])
        plaintext = plaintext[:-padding]
        return plaintext

def save_key_to_file(filename, key):
    with open(filename, 'wb') as file:
        file.write(key)

def load_key_from_file(filename):
    with open(filename, 'rb') as file:
        return file.read()

def main():
    print("CryptoGuard Pro - Verschlüsselungs- und Entschlüsselungstool")

    while True:
        print("\nBitte wählen Sie eine Option:")
        print("1. RSA-Verschlüsselung")
        print("2. RSA-Entschlüsselung")
        print("3. AES-Verschlüsselung")
        print("4. AES-Entschlüsselung")
        print("5. RSA-Schlüssel speichern")
        print("6. RSA-Schlüssel laden")
        print("7. Beenden")

        choice = input("Ihre Auswahl: ")

        if choice == "1":
            private_key, public_key = CryptoToolset.generate_rsa_key_pair()
            plaintext = input("Geben Sie den zu verschlüsselnden Text ein: ")
            encrypted_text = CryptoToolset.rsa_encrypt(public_key, plaintext)
            print("RSA Verschlüsselt:", encrypted_text)

        elif choice == "2":
            private_key = input("Geben Sie Ihren privaten RSA-Schlüssel ein: ")
            ciphertext = input("Geben Sie den verschlüsselten Text ein: ")
            decrypted_text = CryptoToolset.rsa_decrypt(private_key, ciphertext)
            print("RSA Entschlüsselt:", decrypted_text)

        elif choice == "3":
            aes_key = CryptoToolset.generate_aes_key()
            plaintext = input("Geben Sie den zu verschlüsselnden Text ein: ")
            encrypted_text = CryptoToolset.aes_encrypt(aes_key, plaintext)
            print("AES Verschlüsselt:", encrypted_text)

        elif choice == "4":
            aes_key = input("Geben Sie Ihren AES-Schlüssel ein: ")
            ciphertext = input("Geben Sie den verschlüsselten Text ein: ")
            decrypted_text = CryptoToolset.aes_decrypt(aes_key, ciphertext)
            print("AES Entschlüsselt:", decrypted_text)

        elif choice == "5":
            private_key, public_key = CryptoToolset.generate_rsa_key_pair()
            private_key_file = input("Geben Sie den Dateinamen für den privaten RSA-Schlüssel ein: ")
            public_key_file = input("Geben Sie den Dateinamen für den öffentlichen RSA-Schlüssel ein: ")
            save_key_to_file(private_key_file, private_key)
            save_key_to_file(public_key_file, public_key)
            print("RSA-Schlüssel wurden gespeichert.")

        elif choice == "6":
            private_key_file = input("Geben Sie den Dateinamen für den privaten RSA-Schlüssel ein: ")
            public_key_file = input("Geben Sie den Dateinamen für den öffentlichen RSA-Schlüssel ein: ")
            if os.path.exists(private_key_file) and os.path.exists(public_key_file):
                private_key = load_key_from_file(private_key_file)
                public_key = load_key_from_file(public_key_file)
                print("RSA-Schlüssel wurden geladen.")
            else:
                print("Die angegebenen Dateien existieren nicht.")

        elif choice == "7":
            print("Das CryptoGuard Pro-Programm wird beendet.")
            break

        else:
            print("Ungültige Auswahl. Bitte wählen Sie eine gültige Option.")

if __name__ == "__main__":
    main()
