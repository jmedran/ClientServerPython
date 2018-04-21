import socket
import cPickle as pickle

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
random_generator = Random.new().read


def main():
    host = '127.0.0.1'
    port = 5000

    s = socket.socket()
    s.bind((host,port))

    s.listen(1)
    c, addr = s.accept()
    print "Connection from: "+str(addr)
    while True:
        data = c.recv(1024)
        if not data:
            break
        print "from connected user: "+str(data)

        print "Start the SSL Handshake..."
        a = raw_input('Press enter to generate the key pair. ')

        key = RSA.generate(1024, random_generator)
        public_key = key.publickey()

        print "Key pair generated"
        a = raw_input('Press enter to send public key to client ')

        print "Sending key..."

        pickle_Key = pickle.dumps(public_key)

        if c.send(pickle_Key):
            print "Public Key Sent"

        print "Waiting for secret list..."

        pickle_list = c.recv(1024)

        secret_list = pickle.loads(pickle_list)

        print "List received."

        a = raw_input('Press enter to check the information from the list. ')

        enc_data = secret_list[0]

        decrypted_info = key.decrypt(enc_data)

        match_or_not = SHA256.new(decrypted_info).digest() == secret_list[1]

        if match_or_not:
            print "Info Matches. Sending the ciphertext..."

        info_to_be_encrypted = "It seems all secure. Let's talk!"
        aes = AES.new(decrypted_info, AES.MODE_ECB)
        cipher_text = aes.encrypt(info_to_be_encrypted)

        c.send(cipher_text)
        print "Ciphertext sent."



if __name__ == '__main__':
    main()