import errno
import socket
import ssl
import threading
import signal
import requests

host = '127.0.0.1'
port = 8080

#------------Handling client----------------
def handle_client(client_socket):
    if client_socket.fileno() != -1: #  Check if the client's socket is closed
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
                
                # Correction du requête
                if host_web == 'example.com' and host_web != None and port_web != None:
                    print(message)
                    message = _remove(message)
                    try:
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
    try:
        message_ = _decode(message)
        message_ = message_.split("\n")   

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
            
        #-----Port_web-----  
        port_web = message_[0]
        port_web = port_web.split(" ")
        port_web = port_web[1]
        port_web = port_web.split(":") 
        if port_web[0] == 'http' or port_web[1] == 80 or not port_web[0]:
            port_web = 80
        else:
            port_web = int(port_web[1]) 

        return host_web, port_web
    
    except:
        return None, None

        
#-----Connection du client au serveur cible-----
def handle_destination_server(host_web, port_web,client_socket, message):
    print(f'Connecting to: {host_web}')
    try:
        destination_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if port_web != 80: # HTTPS
            destination_server.connect((host_web, port_web))
            # client_socket.sendall('HTTP/1.1 200 Connection Established\r\n\r\n')
            destination_server.sendall(message)
            context = ssl.create_default_context()
            context.load_verify_locations('test/server/ssl/ca.pem', 'test/server/ssl/cert-key.pem')
            wrapped_client = context.wrap_socket(client_socket, server_side=True, do_handshake_on_connect=False)
            while True:
                server_response = requests.get('https://example.com')
                if len(server_response) > 0:
                    server_response = server_response.replace(b'Connection: close', b'Connection: keep-alive')
                    # client_socket.sendall(server_response)
                    wrapped_client.do_handshake()
                    wrapped_client.sendall(server_response)
                else:
                    break 
            
            destination_server.close()       
        else: # HTTP
            destination_server.connect((host_web, port_web))           
                            # '104.18.40.186'  hostinger.co.id    example.com:93.184.216.34  mid.gov.mg:102.16.18.73
            # client_socket.sendall('HTTP/1.1 200 Connection Established\r\n\r\n')
            # Sending the request to server
            destination_server.sendall(message)        
            while True:
                server_response = destination_server.recv(1024)
                print('-------------------------')
                print(server_response)
                if len(server_response) > 0:
                    client_socket.sendall(server_response)
                    #-------------------------------------------------------------------------------
                    #------MILA AMPINA STOP ETO FA LASA MISEND RESPONSE FOANA LAY SERVEUR-----------
                    #-------------------------------------------------------------------------------
                else:
                    break                    

        destination_server.close()
    except :
       print('Connexion fermée par le serveur web')
    finally:
        client_socket.close()
        destination_server.close()
        if 'wrapped_client' in locals() or 'wrapped_client' in globals():
            wrapped_client.close()    

#-------------Remove the error int the request due to the domain being wronged-----------
def _remove(message:bytes):
    message = message.decode('utf-8')
    message = message.split(' ')
    message[1] = '/'
    message = ' '.join(message)
    message = b'' + message.encode()
    return message

#------------Stopping the server manually-----------------
def signal_handler(server,signal, frame):
    print('[SERVER] Stopping the server...')
    server.close()
    
#-------------Decoding the message since some have different format--------------
def _decode(message:any):
    try:
        message = message.decode('utf-8')
        return message
    except UnicodeDecodeError:
        try:
            message = message.decode('ISO-8859-1')
            return message
        except UnicodeDecodeError:
            try:
                message = message.decode('Windows-1252')
                return message
            except:
                return None   
    
           
#-------------Starting proxy------------------
def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    server.bind((host,port))
    server.listen(1)

    # Server SSL configuration
    # context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256')
    # context.check_hostname = False
    # context.verify_mode = ssl.CERT_NONE
    # context.load_verify_locations('test/server/ssl/ca.pem', 'test/server/ssl/key.pem')
    # wrapped_server = context.wrap_socket(server, server_side=True)
    # wrapped_server.listen(1)
    print('[SERVER]  The server is on...')
    while True:
        try:
            # global client_socket
            client_socket, client_addr = server.accept()
            # print(f"Client is connected at: {client_addr[0]}:{port}")
            threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()
            signal.signal(signal.SIGINT, signal_handler)
        except ConnectionResetError:
            print("[ERROR] Connection reset")
        except OSError as e :
            if e.errno != errno.EINTR:
                raise

start()
