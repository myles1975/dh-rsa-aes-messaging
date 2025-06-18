import argparse, select, socket, sys
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

# Function encrypts message
# Citation used info from https://pycryptodome.readthedocs.io/en/latest/src/
# examples.html#encrypt-data-with-aes and https://pycryptodome.readthedocs.io
# /en/latest/src/util/util.html for inspiration and reference
def encrypt_message(plaintext, Ek1, HMACk2):
        
    # gets info to format encrypted message
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(Ek1, AES.MODE_CBC, iv)
    pad_plaintext = pad(str(len(plaintext)).encode(), AES.block_size)
    Ek1_length = cipher.encrypt(pad_plaintext)
    hmack2_length = HMAC.new(HMACk2, iv + Ek1_length, SHA256).digest()
    pad_plaintext = pad(plaintext.encode(), AES.block_size)
    encrypted_message = cipher.encrypt(pad_plaintext)
    hmac = HMAC.new(HMACk2, encrypted_message, SHA256).digest()
    
    # formats message to send
    formatted_message = iv + Ek1_length + hmack2_length + encrypted_message + hmac
        
    return formatted_message

# Function decrypts message
# Ciation: used https://pycryptodome.readthedocs.io/en/latest/src/hash/hmac.
# html and https://pycryptodome.readthedocs.io/en/latest/src/util/util.html for 
# inspiration and reference
def decrypt_message(ciphertext, Ek1, hmac_key, server):
    # breaks message into appropiate parts
    iv = ciphertext[:16]
    Ek1_length = ciphertext[16:32]
    hmack2_length = ciphertext[32:64]
    encrypted_message = ciphertext[64:80]
    hmac = ciphertext[80:]
        
    # verifies hmac
    to_verify = HMAC.new(hmac_key, iv + Ek1_length, SHA256)
    try:
        to_verify.verify(hmack2_length)
    except ValueError:
        sys.stdout.write("ERROR: HMAC verification failed")
        sys.exit()

    # decrypts message
    cipher = AES.new(Ek1, AES.MODE_CBC, iv)
    Ek1_decrypt = cipher.decrypt(Ek1_length)
    decrypt_len = unpad(Ek1_decrypt, AES.block_size)
    decrypted_message = cipher.decrypt(encrypted_message)
    decrypt_msg = unpad(decrypted_message, AES.block_size)
    msg = decrypt_msg.decode()

    return msg

# Fixed key length using SHA256
def fix_key(confkey, authkey):
    return SHA256.new(confkey.encode()).digest(), SHA256.new(authkey.encode()).digest()

# starts server and sends and recieve messages from client
def server(confkey, authkey):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('127.0.0.1', 9999))
        server.listen(1)
        conn, addr = server.accept()

        read_list = [sys.stdin, conn]

        try:
            while True:
                ready_read, _, _ = select.select(read_list, [], [])

                for sock in ready_read:
                    if sock == sys.stdin:
                        try:
                            msg = sys.stdin.readline()

                            if not msg:
                                server.close()
                                return

                            if len(msg) <= 15:
                                encrypted_msg = encrypt_message(msg, confkey, authkey)
                                conn.send(encrypted_msg)
                            else:
                                chunk_size = 15

                                for i in range(0, len(msg), chunk_size):
                                    chunk = msg[i:i + chunk_size]
                                    encrypted_chunk = encrypt_message(chunk, confkey, authkey)
                                    conn.send(encrypted_chunk)

                        except EOFError:
                            server.close()
                            return
                    elif sock == conn:
                        msg = conn.recv(112)

                        if not msg:
                            server.close()
                            return
                        
                        decrypted_msg = decrypt_message(msg, confkey, authkey, server)
                        sys.stdout.write(decrypted_msg)
                        sys.stdout.flush()

        except KeyboardInterrupt:
            server.close()

# starts client and sends messages and recieves from server
def client(confkey, authkey):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        server_address = (sys.argv[2], 9999)
        client.connect(server_address)

        read_list = [sys.stdin, client]

        try:
            while True:
                ready_read, _, _ = select.select(read_list, [], [])

                for sock in ready_read:
                    if sock == sys.stdin:
                        try:
                            msg = sys.stdin.readline()

                            if not msg:
                                client.close()
                                return

                            if len(msg) <= 15:
                                encrypted_msg = encrypt_message(msg, confkey, authkey)
                                client.send(encrypted_msg)
                            else:
                                chunk_size = 15

                                for i in range(0, len(msg), chunk_size):
                                    chunk = msg[i:i + chunk_size]
                                    print(i, chunk)
                                    encrypted_chunk = encrypt_message(chunk, confkey, authkey)
                                    client.send(encrypted_chunk)

                        except EOFError:
                            client.close()
                            return
                    elif sock == client:
                        msg = client.recv(112)

                        if not msg:
                            client.close()
                            return

                        decrypted_msg = decrypt_message(msg, confkey, authkey, server)
                        sys.stdout.write(decrypted_msg)
                        sys.stdout.flush()

        except KeyboardInterrupt:
            client.close()
      
# gets command line arguement and calls corresponding function
def get_commandline():
    if sys.argv[1] == '--s':
        if sys.argv[2] != "--confkey" or sys.argv[4] != "--authkey":
            print("Usage: python encryptedim.py [--s|--c hostname] [--confkey K1] [--authkey K2]")
            return
        
        confkey, authkey = fix_key(sys.argv[3], sys.argv[5])
        
        
        server(confkey, authkey)
        
    elif sys.argv[1] == '--c':
        if sys.argv[3] != "--confkey" or sys.argv[5] != "--authkey":
            print("Usage: python encryptedim.py [--s|--c hostname] [--confkey K1] [--authkey K2]")
            
        confkey, authkey = fix_key(sys.argv[4], sys.argv[6])
                
        client(confkey, authkey)
        
    else:
        return

get_commandline()