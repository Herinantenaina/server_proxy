import socket
import ssl
import threading
import certifi
import requests

# _host = socket.gethostbyname(socket.gethostname())
# print(_host)
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
            host_web, port_web=  extract_port_host_method_request(message)
            if host_web == 'example.com':
                # Correction du requête
                message = _remove(message)
                try:
                    print(message)
                    handle_destination_server(host_web, port_web,client_socket, message)
                except Exception as e:
                    print(e) 
            
        client_socket.close()
    except ConnectionResetError:
        print("[ERROR] Connection error")
    finally:
        client_socket.close()


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
    try:
        ip_web = f"'{socket.gethostbyname(host_web)}'"
    except:
        print("Wrong domain name entered: [",host_web,"]" )
        
    #-----port_web-----
    port_web = message_[0]
    port_web = port_web.split(" ")
    port_web = port_web[1]
    port_web = port_web.split(":")  
    if port_web[1] != '443':
        port_web = 80
    else:
        port_web = int(port_web[1])  

    return host_web, port_web
        

#-----Connection du client au serveur cible-----
def handle_destination_server(host_web, port_web,client_socket, message):
    #--Tsy maintsy ampiasaina pour les https websites--
    print(f'Connecting to: {host_web}')
    try:
        destination_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if port_web != 80:
            destination_server.connect((host_web, 80))
            destination_server.sendall(message)
            while True:
                server_response = destination_server.recv(4096)
                if len(server_response) > 0:
                    server_response = server_response.replace(b'Connection: close', b'Connection: keep-alive')
                    print(server_response.decode())
                    client_socket.sendall(server_response)
                else:
                    break 
            

            destination_server.close()       
        else:
            destination_server.connect((host_web, port_web))           
                            # '104.18.40.186'  hostinger.co.id    example.com:93.184.216.34  mid.gov.mg:102.16.18.73
            # Sending the request to server
            destination_server.sendall(message)             
            while True:
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
    except :
       print('Connexion fermée par le serveur web')
    #  print(f"verify_mode: {context.verify_mode}, check_hostname: {context.check_hostname}")
    finally:
        # wrapped_server.close()
        client_socket.close()
        destination_server.close()    

#-------------Remove the error int the request due to the domain being wronged-----------
def _remove(message:bytes):
    message = message.decode('utf-8')
    message = message.split(' ')
    message[1] = '/'
    message = ' '.join(message)
    message = b'' + message.encode()
    return message

#-------------Starting proxy------------------
def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    server.bind((host,port))
    server.listen(10)

    # Server SSL configuration
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_verify_locations(certifi.where())
    wrapped_server = context.wrap_socket(server, server_side=True)
    print('[SERVER]  The server is on...')
    while True:
        try:
            client_socket, client_addr = wrapped_server.accept()
            # print(f"Client is connected at: {client_addr[0]}:{port}")
            threading.Thread(target=handle_client, args=(client_socket,)).start()
        except ConnectionResetError:
            print("[ERROR] Connection reset")

start()