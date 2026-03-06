import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def client_send(message, key): #client send takes message, and key as input

    aesgcm = AESGCM(key)
    nonce = os.urandom(12) #unique value for aes to gen ciphertext
    message_bytes = message.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, message_bytes, None) #generate ciphertext

    return {
        "nonce": nonce,
        "ciphertext": ciphertext
    } #return nonce and ciphertext so we can pass to middleman to simulate MITM


def middleman_intercept(ciphertext_package): #MITM simulation

    print("\n(MIDDLEMAN) Intercepted ciphertext successful.")
    print("(MIDDLEMAN) Nonce:", ciphertext_package["nonce"].hex())
    print("(MIDDLEMAN) Intercepted Ciphertext:", ciphertext_package["ciphertext"].hex())

    fake_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(fake_key)

    try: #try decrypting with out fake key we just generated above
        decrypted = aesgcm.decrypt(
            ciphertext_package["nonce"],
            ciphertext_package["ciphertext"],
            None
        )
        print("(MIDDLEMAN) This will never happen: ", decrypted.decode("utf-8")) #middleman randoimly guessed correct key
        return True
    except Exception:
        print("(MIDDLEMAN) Decryption failed. Incorrect AES key.") #middleman did not succeed
        return False


def server_receive(ciphertext_package, key): #decrpyt with real key

    aesgcm = AESGCM(key) #real key
    decrypted = aesgcm.decrypt(
        ciphertext_package["nonce"],
        ciphertext_package["ciphertext"],
        None
    )
    return decrypted.decode("utf-8") #return original message


def main():
    original_message = input("Enter your message: ")
    key = AESGCM.generate_key(bit_length=256) #enerate key

    print("Original message:")
    print(original_message)

    ciphertext_package = client_send(original_message, key) #pass our key and message to client_send to encrpyt and "send"

    print("\nEncrypted message:")
    print(ciphertext_package["ciphertext"].hex())

    middleman_success = middleman_intercept(ciphertext_package) #simulate intercept pass middleman ciphertext and nonce

    print("\nCould the middleman decrypt it?")
    print("Yes" if middleman_success else "No")

    final_message = server_receive(ciphertext_package, key) #decrpyt

    print("\nFinal decrypted message at server:")
    print(final_message) #print decrypted original message


if __name__ == "__main__":
    main()
