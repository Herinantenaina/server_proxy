import socket
import ssl
import threading

#host = socket.gethostbyname(socket.gethostname())
host = '127.0.0.1'
print(host)
port = 8080


#------------Handling client----------------
def handle_client(client_socket):
    try:
        # client_socket.setblocking(False)
        while True:
            message = client_socket.recv(1024)
        
            if not message:
                break
            #------Obtention du port, du methode et de l'adresse host------
            host_web, port_web, request_host =  extract_port_host_method_request(message)
            
            handle_destination_server(host_web, port_web, request_host, client_socket)
        
            
        client_socket.close()
    except ConnectionResetError:
        print("[ERROR] Connection error")


#-------------METHOD-PORT-HOST--------------
def extract_port_host_method_request(message):
    message_ = message.decode('utf-8')
    message_ = message_.split("\n")
            
            #-----Method-----
    method = message_[0]
    method = method.split(" ")
    method = method[0]
            
            #----Host_Web----
    host_web = message_[1]
    host_web = host_web.split(':')
    host_web = host_web[1]
    host_web = host_web.split(' ')
    host_web = host_web[1]
    host_web = host_web.strip('\r')
    print(host_web)
    host_web = f"'{socket.gethostbyname(host_web)}'"
        
            #-----port_web-----
    port_web = message_[0]
    port_web = port_web.split(" ")
    port_web = port_web[1]
    port_web = port_web.split(":")  
    if port_web[1] != '443':
        port_web = 80
    else:
        port_web = int(port_web[1])  

        #------Extracting the host request------      
    request_host = str(message).split(" ")
    request_host = request_host[2] + request_host[3]
    request_host = request_host.strip("\r")
    check = '\\'
    if check in request_host:
        request_host = request_host.split("\\r\\n")
        tmp = request_host[1].split(':4')[0]
        request_host = request_host[0] + r'\r\n' + tmp + r'\r\n\r\n'
        request_host = request_host.replace('\\\\', '\\')
    else:
        request_host = request_host.split("\r\n")
        tmp = request_host[1].split(':4')[0]
        request_host = request_host[0] + r'\r\n' + tmp + r'\r\n\r\n'
        request_host = request_host.replace('\\\\', '\\')
    
    request_host = method + ' / ' + request_host
    request_host = request_host.encode('utf-8')
    print(request_host)

    return host_web, port_web, request_host
            



#-------------Starting proxy------------------
def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host,port))
    server.listen(1)
    while True:
        try:
            client_socket, client_addr = server.accept()
            print(f"Client is connected at: {client_addr[0]}:{port}")
            threading.Thread(target=handle_client, args=(client_socket,)).start()
        except ConnectionResetError:
            print("[ERROR] Connection reset")



#-----Connection du client au serveur cible-----
def handle_destination_server(host_web, port_web,request_host,client_socket):
    #Tsy maintsy ampiasaina pour les https websites
    context = ssl.create_default_context()
    destination_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wrapped_server = context.wrap_socket(destination_server, server_hostname= '93.184.216.34')
    wrapped_server.connect(('93.184.216.34', 80))           
                          # '104.18.40.186'  hostinger.co.id
            
            #Send request to server
    wrapped_server.sendall(b'GET / HTTP/1.1\r\nHost:www.example.com\r\n\r\n')
                                # GET / HTTP/1.1\r\nHost:www.example.com\r\n\r\n
                                #      HTTP/1.1\r\nHost: www.example.com\r\n
            #Receive data from destination server
    while True:
        response = wrapped_server.recv(1024)
        print(f"[RESPONSE]{response.decode('utf-8')}")
            #Check if data has a content
        if len(response) > 0:
                    #send the response to the client
            client_socket.send(response)
        else:
            break    

    wrapped_server.close()

start()