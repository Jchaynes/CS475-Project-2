from socket import SOCK_STREAM, AF_INET, socket, MSG_WAITALL
import argparse
import sys
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes


KEYSIZE = 16

parser = argparse.ArgumentParser()
#parser.add_argument("-h","--help",help="-s <server> -p <port>")
parser.add_argument("-a","--address",help="interface address to listen on",required="true")
parser.add_argument("-p","--port",help="listening port",required="true")
args = parser.parse_args()

data = "This is a secret message. Don't give it to coolerseth.".encode("utf-8")

class cryptoClient:
  def __init__(self,socket:socket):
    self.socket = socket
    self.address = None
    self.pub_RSA_key = None
    self.session_key = get_random_bytes(KEYSIZE)

  def read_msg_len(self):
    keyLen = self.socket.recv(4,MSG_WAITALL)
    return keyLen
  

def create_socket(address,port):
  skt = socket(AF_INET,SOCK_STREAM)
  skt.bind(('0.0.0.0', int(args.port)))
  return skt

def encrypt_data(session_key, plaintext):
  print("Encrypting data with encrypted session key")
  #Encrypt the data with AES EAX mode
  cipher_aes = AES.new(session_key,AES.MODE_EAX)
  ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)
  
  file_out = open("encrypted_data.bin", "wb")
  [ file_out.write(x) for x in (session_key, cipher_aes.nonce, tag, ciphertext)]
  file_out.close()
  #write_chunks = [session_key,cipher_aes.nonce,tag,ciphertext]
  #return write_chunks

clients = [cryptoClient]

def listen(skt:socket):
  print("Listening for connections on ", skt)
  while(True):
    con_socket, address = skt.accept()
    print("Accepted connection from ", socket, address)
    
    #Read in Key Length for client RSA key
    client = cryptoClient(con_socket)
    keyLen = client.read_msg_len()
    msg = con_socket.recv(int.from_bytes(keyLen,'little'))

    #Format the read in key to proper RSA key object format.
    try:
      recipient_key = RSA.import_key(msg)
    except:
      print("Error converting RSA key from client: {0}".format(sys.exc_info[0]))
      raise

    #print("RSA key is: " , recipient_key.export_key().decode("utf-8"))
    print("Session Key is: ", client.session_key)

    #Encrypt the AES key with the user's public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(client.session_key)

    #Send the encrypted session Key back to client.
    con_socket.send(sys.getsizeof(enc_session_key).to_bytes(4,'little'))
    con_socket.send(enc_session_key)
    
    #client.socket.send(sys.getsizeof(encrypted_data).to_bytes(4,'little'))

    #client.socket.send(encrypted_data)
    #TODO: Build input loop and remove socket.close()
    client.socket.close()
    return
    #Send the client the encrypted session key, nonce, tag, and their intial string.

def read_client(con_socket:socket, address):
  
  #Read in Key Length for client RSA key
  keyLen = con_socket.recv(4,MSG_WAITALL)
  
  #Read in client RSA key bytes in little endian format
  msg = con_socket.recv(int.from_bytes(keyLen,'little'))

  #Format the read in key to proper RSA key object format.
  try:
    recipient_key = RSA.import_key(msg)
  except:
    print("Error converting RSA key from client: {0}".format(sys.exc_info[0]))
    raise

  #Generate Random AES Key
  session_key = get_random_bytes(16)

  #Encrypt the AES key with the user's public RSA key
  cipher_rsa = PKCS1_OAEP.new(recipient_key)
  enc_session_key = cipher_rsa.encrypt(session_key)
  


  file_in = open("encrypted_data.bin",'rb')
  encrypted_data = file_in.read()
  #encrypted_data = encrypt_data(enc_session_key,data)

  #Send the client the encrypted session key, nonce, tag, and their intial string.



if __name__ == "__main__":

  srv_socket = create_socket(args.address,args.port)
  srv_socket.listen(2)

  t1 = threading.Thread(target=listen(srv_socket))
  t1.start()
  t1.join()