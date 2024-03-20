import socket
import ssl
import time
import threading
import signal

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_cert_chain(certfile='ssl/cert.pem', keyfile='ssl/key.pem')
context.check_hostname = False
host = 'localhost'
port = 8081
# hostname_server = socket.getfqdn()

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
        return None
    
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


def request(client_socket):
    if client_socket.fileno() != -1:
        try:
            while True:
                try:
                    message = client_socket.recv(1024)
                except Exception as e:
                    break

                if not message:
                    break
 
                #------Obtention du port, du methode et de l'adresse host------
                host_web =  extract_port_host_method_request(message)
                if host_web == 'example.com' and host_web != None:
                    print(message)
                    message = _remove(message)
                    print('A client is connected')
                    with socket.create_connection((host_web, 443)) as sock:
                        with context.wrap_socket(sock, server_hostname=host_web) as ssock:
                            ssock.send(message)
                            response = bytes()
                            while True:
                                try:
                                    response= ssock.recv(1024)
                                    message = client_socket.recv(1024)
                                    print(message)
                                    client_socket.sendall(response)
                                    print(response)
                                except Exception as e:
                                    print(e)
                                    break
                                finally:
                                    sock.close()
        except ConnectionError:
            print('Connection error')
        finally:
            client_socket.close()   


#-------------Starting proxy------------------
def start():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        server.bind((host,port))
        server.listen(5)
        print('[SERVER]  The server is on...')
        # server = context.wrap_socket(server, server_side=True)
        while True:
            try:
                client_socket, client_addr = server.accept()
                # client_socket = context.wrap_socket(client_socket, server_side=True)
                threading.Thread(target=request, args=(client_socket,), daemon=True).start()
                signal.signal(signal.SIGINT, signal_handler)
            except ConnectionResetError:
                print("[ERROR] Connection reset")
            except OSError as e :
                raise 
            except KeyboardInterrupt:
                print('[SERVER] The server is stopping...')
                exit(0)


start()