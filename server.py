import socket
import requests
import threading
host = socket.gethostbyname(socket.gethostname())
print(host)
port = 8080

def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host,port))
    server.listen(10)
    while True:
        try:
            threading.Thread(target=handle_client, args=(server,)).start()
        except ConnectionResetError:
            print("ERROR")


def handle_client(server):
    try:
        client_socket, client_addr = server.accept()
        print(f"Client is connected at: {client_addr[0]}:{port}")
        while True:
            message = client_socket.recv(1024)
        
            if not message:
                break

            message_ = message.decode()
            message_ = message_.split("\n")
            message_ = message_[0]
            _,message_,__ = message_.split()
            message_,_ = message_.split(':')
            print(message_)
            
        client_socket.close()
    except ConnectionResetError:
        print("[ERROR]")
        

start()