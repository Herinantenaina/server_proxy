import socket
import ssl
import time
import threading
import signal


#----------Web context-----------
context_web = ssl.create_default_context()
context_web.load_verify_locations('ssl/ca.pem')

#---------Client context---------
context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context_client.load_cert_chain(certfile='ssl/cert.pem', keyfile='ssl/key.pem')
context_client.load_verify_locations(cafile='ssl/ca.pem')

#----------Server context--------
context_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context_server.load_cert_chain(certfile='ssl/cert.pem', keyfile='ssl/key.pem')
context_server.check_hostname = True
context_server.verify_mode = ssl.CERT_REQUIRED

host = 'localhost'
port = 8080
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
            host_web = None

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
    message[0] = 'GET'
    message[1] = '/'
    message = ' '.join(message)
    message = b'' + message.encode()
    return message


#------------Stopping the server manually-----------------
def signal_handler(signal, frame):
    print('[SERVER] Stopping the server...')
    exit(0)


def request(_client_socket):
    if _client_socket.fileno() != -1:
        try:
            while True:
                try:
                    message = _client_socket.recv(1024)
                except Exception as e:
                    print(e)
                    break
                
                if not message:
                    break
                
                #------Obtention du port, du methode et de l'adresse host------
                host_web =  extract_port_host_method_request(message)
                if host_web == 'example.com' and host_web != None:
                    message = _remove(message)
                    print('A client is connected')
                    
                    with socket.create_connection((host_web, 443)) as web:
                        with context_web.wrap_socket(web, server_hostname=host_web) as secure_web:
                            _client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                            client_socket = context_client.wrap_socket(_client_socket, server_side=True, do_handshake_on_connect=False)
                            try:
                                print('Performing handshake')
                                client_socket.do_handshake()
                            except Exception as e:
                                print(e,'+++++++++++')
                                print('Handshake failed')
                            data = client_socket.recv(4096)
                            print(data)
                            secure_web.sendall(message)
                            while True:
                                try:
                                    response= secure_web.recv(4096)
                                    if not response:
                                        break
                                    client_socket.sendall(response)
                                    print(response)
                                except Exception as e:
                                    print(e)
                                    break
                                finally:
                                    secure_web.shutdown(socket.SHUT_RDWR)
                                    secure_web.close()
                                    client_socket.shutdown(socket.SHUT_RDWR)
                                    client_socket.close()
            _client_socket.close()  

        except ConnectionError:
            print('Connection error')
        finally:
            _client_socket.shutdown(socket.SHUT_RDWR)
            _client_socket.close()  


#-------------Starting proxy------------------
def start():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        server.bind((host,port))
        server.listen(5)
        # secure_server = context_server.wrap_socket(server, server_hostname='localhost')
        # secure_server.bind((host,port))
        # secure_server.listen(5)
        print('[SERVER]  The server is on...')
        # server = context.wrap_socket(server, server_side=True)
        try:
            signal.signal(signal.SIGINT, signal_handler)
            while True:
                try:
                    try:
                        _client_socket, client_addr = server.accept()
                        threading.Thread(target=request, args=(_client_socket,), daemon=True).start()
                    except Exception as e:
                        print(e,'-------------------')
                except ConnectionResetError:
                    print("[ERROR] Connection reset")
                except OSError as e :
                    raise 
        except KeyboardInterrupt:
                print('[SERVER] The server is stopping...')
                exit(0)

start()