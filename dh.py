import sys, socket, random

# prime number
p = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b
# base
g = 2

# starts client and performs DH key exchange
def client():
    # connects to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((sys.argv[2], 9999))

        # generates random a
        a = random.randint(1, p - 1)
        
        # calculates A
        A = pow(g, a, p)

        # sends A
        client.send(bytes(str(A) + '\n', 'utf-8'))

        # recieves B
        msg = client.recv(1024)
        B = int(msg.decode('utf-8').strip())

        # calulates and prints K
        K = pow(B, a, p)
        sys.stdout.write(str(K))
        sys.stdout.flush()

# starts client and performs DH key exchange
def server():
    # starts server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('127.0.0.1', 9999))
        server.listen()

        # accepts connection with client
        conn, addr = server.accept()
        
        with conn:
            # receives A
            msg = conn.recv(1024)
            A = int(msg.decode('utf-8').strip())

            # generates random exponent b
            b = random.randint(1, p - 1)
            
            # calculates B
            B = pow(g, b, p)

            # sends B
            conn.send(bytes(str(B) + '\n', 'utf-8'))

            # calculates and prints K
            K = pow(A, b, p)
            sys.stdout.write(str(K))
            sys.stdout.flush()

# starts server or client based on input
def get_commandline():
    if sys.argv[1] == '--s':
        server()
    elif sys.argv[1] == '--c':            
        client()
    else:
        return

get_commandline()