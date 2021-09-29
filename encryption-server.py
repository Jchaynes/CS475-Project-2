from socket import SOCK_STREAM, AF_INET, socket, MSG_WAITALL,htons,ntohs
import argparse
import sys
import threading
from typing import ByteString
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes



  # 1. Server listens on port
  # 2. Client connects to port
  # 3. Client sends public RSA key (4 bytes unsigned)
  # 4. Server generates AES session key (16 bytes unsigned)
  # 5. Server encrypts AES key with RSA key
  # 6. Server sends encrypted key to client and waits
  # 7. Client decrypts session key
  # 8. Client encrypts either hardcoded string or user input with session key (Send length first, up to 4 bytes unsigned)
  # 9. Client sends message to confirm receipt and decryption of key (Send length first, up to 4 bytes unsigned)
  # 10. Server decrypts message from client with session key
  # 11. Server sends hardcoded or user input message encrypted with session key

KEYSIZE = 16

parser = argparse.ArgumentParser()
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
  
  def send(self,message : bytes):
    msgLen = sys.getsizeof(message)#.to_bytes(4,'little')
    self.socket.send(msgLen.to_bytes(4,sys.byteorder))
    self.socket.send(message)


clients = [cryptoClient]

def create_socket(address,port):
  skt = socket(AF_INET,SOCK_STREAM)
  skt.bind(('0.0.0.0', int(args.port)))
  return skt

def decrypt_data(session_key,nonce,tag, ciphertext):
  cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
  data = cipher_aes.decrypt_and_verify(ciphertext, tag)
  return  data.decode("utf-8")

def encrypt_data(session_key, plaintext):
  print("Encrypting data with session key")
  #Encrypt the data with AES EAX mode
  cipher_aes = AES.new(session_key,AES.MODE_EAX)
  ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

  chunks = [cipher_aes.nonce,tag,ciphertext]
  data = b''.join(chunks)
  nonce_len = sys.getsizeof(cipher_aes.nonce)
  tag_len = sys.getsizeof(tag)
  ciphertext_len = sys.getsizeof(ciphertext)
  print("Message size is:", data, sys.getsizeof(data))

  print("Nonce: ", cipher_aes.nonce, nonce_len)
  print("Tag: ", tag,  tag_len)
  print("Ciphertext: ", ciphertext, ciphertext_len)
  return data

def parse_encrypted_msg(enc_msg : bytes):
  if(len(enc_msg < 33)):
    raise OSError
  nonce = enc_msg[0:16]
  tag = enc_msg[16:32]
  ciphertext = enc_msg[32:]
  return (nonce,tag,ciphertext)

def listen(skt:socket):
  print("Listening for connections on ", skt)
  #2. Client connects to port
  con_socket, address = skt.accept()
  print("Accepted connection from ", con_socket, address)
  
  #Read in Key Length for client RSA key
  client = cryptoClient(con_socket)
  keyLen = client.read_msg_len()
  #3. Recieve RSA Key
  msg = con_socket.recv(int.from_bytes(keyLen,'little'))

  #Format the read in key to proper RSA key object format.
  try:
    recipient_key = RSA.import_key(msg)
  except:
    print("Error converting RSA key from client: {0}".format(sys.exc_info[0]))
    raise

  #5. Encrypt the AES key with the user's public RSA key
  cipher_rsa = PKCS1_OAEP.new(recipient_key)
  enc_session_key = cipher_rsa.encrypt(client.session_key)

  #6. Send the encrypted session Key back to client.
  con_socket.send(sys.getsizeof(enc_session_key).to_bytes(4,'little'))
  con_socket.send(enc_session_key)

  #9. Read message from client.
  client_msg_len = client.socket.recv(4, MSG_WAITALL)
  client_msg = client.socket.recv(client_msg_len)
  
  #10. Decrypt the message with AES session key
  nonce,tag,ciphertext = parse_encrypted_msg(client_msg)
  decrypted_client_msg = decrypt_data(client.session_key,nonce,tag,ciphertext)
  print(decrypted_client_msg)


  encrypted_data = encrypt_data(client.session_key,data)
  client.send(encrypted_data)
  client.socket.close()
  return
  #Send the client the encrypted session key, nonce, tag, and their intial string.

def read_client(client:cryptoClient):
  # while(True):
    #Read in Key Length for client RSA key
    print("reading data from the client...")
    keyLen = client.socket.recv(4,MSG_WAITALL)
    print("Reading in data length of %d " % (int.from_bytes(keyLen,'little')))
    if(int.from_bytes(keyLen,'little') > 0):      #Read in client RSA key bytes in little endian format
      msg = client.socket.recv(int.from_bytes(keyLen,'little'))
      print(msg)
      nonce = msg[:16]
      tag = msg[16:32]
      ciphertext = msg[32:]
      
    
      print(decrypt_data(client.session_key,nonce,tag,ciphertext))
    return


def send_client(client:cryptoClient):
  # while(True):
    print("Beggining chat with client.")
    encrypted_string = encrypt_data(client.session_key,data)
    client.send(encrypted_string)
    userString = input("Chat: ")
    if(userString.lower() == "quit"):
      return
    encrypted_string = encrypt_data(client.session_key,userString)
    client.send(encrypted_string)
  


if __name__ == "__main__":

  srv_socket = create_socket(args.address,args.port)
  srv_socket.listen(2)
  #while(True):
  listen(srv_socket)