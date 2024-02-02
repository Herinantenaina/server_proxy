import socket
import requests
import threading
#host = socket.gethostbyname(socket.gethostname())
host = '127.0.0.1'
print(host)
port = 8080

def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host,port))
    server.listen(10)
    while True:
        try:
            client_socket, client_addr = server.accept()
            threading.Thread(target=handle_client, args=(client_socket,)).start()
        except ConnectionResetError:
            print("[ERROR] Connection reset")


def handle_client(client_socket):
    try:
        # client_socket.setblocking(False)
        print(f"Client is connected at: {client_addr[0]}:{port}")
        data = b''
        while True:
            message = client_socket.recv(1024)
        
            if not message:
                break
            #------Obtention du port, du methode et de la adresse host------
            request = data + message
            message_ = message.decode('utf-8')
            message_ = message_.split("\n")
            
            #-----Method-----
            method = message_[0]
            method = method.split(" ")
            method = method[0]
            
            #----Host_Web----
            host_web = message_[1]
            host_web = host_web.split(" ")
            host_web = host_web[1]
            host_web = host_web.split(":")
            host_web = host_web[0]

            #port_web
            port_web = message_[0]
            port_web = port_web.split(" ")
            port_web = port_web[1]
            port_web = port_web.split(":")  
            if port_web[1] != '443':
                port_web = 80
            else:
                port_web = int(port_web[1])
            
            print(f"Connecting to {host_web}:{port_web}")

        #     #-----Connection du client au serveur cible-----
        #     destination_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #     destination_server.connect((host_web, port_web))           
            
        #     #Send request to server
        #     destination_server.sendall(request)
            
        #     #Receive data from destinatin server
        #     while True:
        #         response = destination_server.recv(1024)
        #         print(f"[RESPONSE]{response.decode('utf-8')}")
        #         #Check if data has a content
        #         if len(data) > 0:
        #             #send the response to the client
        #             client_socket.send(response)
        #         else:
        #             break
        # destination_server.close()
        client_socket.close()
    except ConnectionResetError:
        print("[ERROR] Connection error")
        

start()