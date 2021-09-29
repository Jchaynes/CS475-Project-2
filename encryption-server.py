from socket import SOCK_STREAM, AF_INET, socket, MSG_WAITALL
import argparse
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes


parser = argparse.ArgumentParser()
#parser.add_argument("-h","--help",help="-s <server> -p <port>")
parser.add_argument("-a","--address",help="interface address to listen on",required="true")
parser.add_argument("-p","--port",help="listening port",required="true")
args = parser.parse_args()

data = "This is a secret message. Don't give it to coolerseth.".encode("utf-8")

def create_socket(address,port):
    skt = socket(AF_INET,SOCK_STREAM)
    skt.bind(('0.0.0.0', int(args.port)))
    return skt


def main():

    srv_socket = create_socket(args.address,args.port)
    srv_socket.listen()
    potential_readers = [socket]
    potential_writers = [socket]
    potential_errs = [socket]

    print("Listening for connections on ", srv_socket)
    con_socket,address = srv_socket.accept()
    print("Accepted connection from ", socket, address)
    keyLen = con_socket.recv(4,MSG_WAITALL)
  #  print(keyLen)
    print("Key length is: " , int.from_bytes(keyLen,'little'))
    msg = con_socket.recv(int.from_bytes(keyLen,'little'))
    #con_socket.send(b'This is a less secret message.')
    print("Received Public Key of : ", msg)

    #Write out the recieved RSA key
    file_out = open('receiver.pem', 'wb')
    file_out.write(msg)
    file_out.close()

    #Read in a stored RSA key
    recipient_key = RSA.import_key(open("receiver.pem").read())
    session_key = get_random_bytes(16)

    #Encrypt the AES key with the user's public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    #Encrypt the data with AES EAX mode
    cipher_aes = AES.new(session_key,AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    print("Encrypted %s with user RSA key" % (session_key))

    file_out = open("encrypted_data.bin", "wb")
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    file_out.close()

    file_in = open("encrypted_data.bin",'rb')
    encrypted_data = file_in.read()
    print("Preparing to send encrypted data: ", encrypted_data)


    con_socket.send(sys.getsizeof(encrypted_data).to_bytes(4,'little'))
    con_socket.send(encrypted_data)
    con_socket.close()

main()
