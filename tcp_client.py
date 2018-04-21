import socket
import cPickle as pickle


from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
random_generator = Random.new().read


def main():
    host = '127.0.0.1'
    port = 5000

    s = socket.socket()
    s.connect((host,port))



    message = raw_input("-> ")
    while message != 'q':
        s.send(message)

        pickle_key = s.recv(1024)
        public_key = pickle.loads(pickle_key)
        print 'Received from server: '+str(public_key)

        message = raw_input("->Press enter to verify the public key.")
        print "Public Key verified!"
        message = raw_input("-> Press enter to prepare the secret list.")
        print "Client prepares the secret list."

        secret_piece = Random.get_random_bytes(16)
        enc_data = public_key.encrypt(secret_piece, 12)
        hash_value = SHA256.new(secret_piece).digest()
        L = [enc_data, hash_value]

        pickle_list = pickle.dumps(L)

        print "List is ready."
        message = raw_input("-> Press enter to send the list")

        s.send(pickle_list)
        print "List sent."
        print "Waiting for ciphertext from the server..."

        cipher_text = s.recv(1024)
        print "Cipher text recieved."
        print "The encrypted message is: " + cipher_text

        message = raw_input("-> Press enter to decrypt the cipher text")

        aes = AES.new(secret_piece, AES.MODE_ECB)

        print "The decrypted message is: " + aes.decrypt(cipher_text)

    s.close()
if __name__ == '__main__':
    main()