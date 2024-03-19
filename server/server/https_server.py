import errno
import socket
import threading
import signal
import ssl

host = 'localhost'
port = 8081
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='ssl/cert.pem', keyfile='ssl/key.pem')


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
                host_web=  extract_port_host_method_request(message)
                
                # Correction du requête
                if host_web == 'example.com' and host_web != None:
                    message = _remove(message)
                    try:
                        handle_destination_server(host_web, client_socket, message)
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
    

        return host_web
    except:
        return None,

        
#-----Connection du client au serveur cible-----
def handle_destination_server(host_web, client_socket, message):
    print(f'Connecting to: {host_web}')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as destination_server:
            destination_server.connect((host_web, 80))
            destination_server.sendall(message)
            
            while True:
                    server_response = destination_server.recv(1024)
                    if len(server_response) > 0:
                        client_socket.sendall(server_response)
                    else:
                        break 
                    
            destination_server.close()
    except Exception as e:
       print(e,'[Fermé par le serveur]')
    finally:
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

#------------Stopping the server manually-----------------
def signal_handler(signal, frame):
    print('[SERVER] Stopping the server...')
    exit(0)
    
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
    server.listen(5)
    
    print('[SERVER]  The server is on...')
    while True:
        try:
            client_socket, client_addr = server.accept()
            # Wrapping the client_socket to use ssl/tsl encryption
            client_socket = context.wrap_socket(client_socket, server_side= True)
            threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()
            signal.signal(signal.SIGINT, signal_handler)
        except ConnectionResetError:
            print("[ERROR] Connection reset")
        except OSError as e :
            if e.errno != errno.EINTR:
                raise
        except KeyboardInterrupt :
            print('[SERVER] The server is stopping...')
            exit(0)


start()
