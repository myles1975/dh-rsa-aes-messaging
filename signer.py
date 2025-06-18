import sys, socket, binascii
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# creates rsa key-pair and saves to file
# used https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
def rsa():
    mykey = RSA.generate(3072)
    pubkey = mykey.public_key().export_key()
    
    with open("mypubkey.pem", "wb") as f:
        f.write(pubkey)
        
    with open("myprivatekey.pem", "wb") as f:
        data = mykey.export_key()
        f.write(data)
        
# connects to server and sends message with signature
# used https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_v1_5.html
# and https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
def client():
     
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((sys.argv[2], 9998))   
        
        # generates signature in hex
        message = sys.argv[4].encode('utf-8') 
        key = RSA.import_key(open('myprivatekey.pem').read())
        h = SHA256.new(message)
        signature = pkcs1_15.new(key).sign(h) 
        signature_hex = binascii.hexlify(signature).decode() 
        
        # pads messages
        padded_message_length = '0' * (4 - len(str(len(message)))) + str(len(message))
        padded_signature_length = '0' * (4 - len(str(len(signature_hex)))) + str(len(signature_hex))

        # format
        message_to_send = padded_message_length.encode('utf-8') + message + padded_signature_length.encode('utf-8') + signature_hex.encode('utf-8')

        client.send(message_to_send)

def get_commandline():
    if sys.argv[1] == '--genkey':
        rsa()
    elif sys.argv[1] == '--c':            
        client()
    else:
        return

get_commandline()