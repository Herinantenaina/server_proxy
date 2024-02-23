import socket
import ssl
import threading
import requests
import  time 

#host = socket.gethostbyname(socket.gethostname())
host = '127.0.0.1'
port = 8080


#------------Handling client----------------
def handle_client(client_socket):
    try:
    # client_socket.setblocking(False)
        while True:
            try:
                message = client_socket.recv(1024)
            except Exception as e:
                print(e)
                break

            if not message:
                break
            #------Obtention du port, du methode et de l'adresse host------
            host_web, port_web, method =  extract_port_host_method_request(message)
            handle_destination_server(host_web, port_web,client_socket,method, message) 
            # print(message)
            

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
    print(f'Connecting to: {host_web}')
    try:
        host_web = f"'{socket.gethostbyname(host_web)}'"
    except:
        print("Wrong domain name entered")
        
    #-----port_web-----
    port_web = message_[0]
    port_web = port_web.split(" ")
    port_web = port_web[1]
    port_web = port_web.split(":")  
    if port_web[1] != '443':
        port_web = 80
    else:
        port_web = int(port_web[1])  

    return host_web, port_web, method
        

#-----Connection du client au serveur cible-----
def handle_destination_server(host_web, port_web,client_socket, method, message):
    #--Tsy maintsy ampiasaina pour les https websites--
    try:
        # context = ssl.create_default_context()
        # context.verify_mode = ssl.CERT_NONE
        # context.check_hostname = False
        destination_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # wrapped_server = context.wrap_socket(destination_server, server_hostname= '93.184.216.34')
        destination_server.connect(('mid.gov.mg', 80))           
                            # '104.18.40.186'  hostinger.co.id    example.com:93.184.216.34  mid.gov.mg:102.16.18.73
        #Sending the request to server
        destination_server.sendall(b'GET / HTTP/1.1\r\nHost:www.example.com\r\n\r\n')             
        while True:
            # server_response = requests.get('http://www.example.com') 
            server_response = destination_server.recv(1024)
                #Check if data has a content
            if len(server_response) > 0:
                # send the server_response to the client
                client_socket.sendall(server_response)
                #-------------------------------------------------------------------------------   
                #------MILA AMPINA STOP ETO FA LASA MISEND RESPONSE FOANA LAY SERVEUR-----------
                #-------------------------------------------------------------------------------
            else:
                break    

        destination_server.close()
    except Exception as e:
       print(e)

#-------------Starting proxy------------------
def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host,port))
    server.listen(10)
    print('[SERVER]  The server is on...')
    while True:
        try:
            client_socket, client_addr = server.accept()
            print(f"Client is connected at: {client_addr[0]}:{port}")
            threading.Thread(target=handle_client, args=(client_socket,)).start()
        except ConnectionResetError:
            print("[ERROR] Connection reset")
start()