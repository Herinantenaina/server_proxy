import socket
import ssl
import threading
import signal
import certifi
import subprocess
import os
import re

#----------Web context-----------
context_web = ssl.create_default_context()
context_web.load_verify_locations('ssl/ca.pem', certifi.where())


host = '127.0.0.1'
port = 8080
# hostname_server = socket.getfqdn()

#-------------Searching the openssl.exe directory------------
def openssl_path():
    for root, _, files in os.walk(os.environ["ProgramFiles"]):
        if "openssl.exe" in files:
            path = os.path.join(root, "openssl.exe")
            path = path.split('\\openssl.exe')
            return path[0]
            
    raise FileNotFoundError("OpenSSL n'existe sur se système")

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
            f"'{socket.gethostbyname(host_web)}'"
        except:
            print("Wrong domain name entered: [",host_web,"]" )   
            host_web = None

        return host_web
    except:
        return None

#-------------Mise à jour du extfile.cnf------------
def suppression_doublon(host_web):
    if host_web in open('ssl/extfile.cnf', 'r').read():
        count = 0
        line_to_remove = 0
        numberOfLines  = 0
        lines = 0
        with open('ssl/extfile.cnf', 'r') as file:
            lines = file.readlines()
            for line in lines:
                numberOfLines += 1
                if host_web in line:
                    count += 1
                    line_to_remove = numberOfLines
            if count > 1:
                del lines[line_to_remove - 1]
                
                #--------Rectification des numérotations du liste-------
                count = 0
                for line in lines:
                    count += 1
                    if  'DNS' in line:
                        line = re.sub(r"^DNS\.\d+ =", f"DNS.{count - 4} =", line)
                        lines[count - 1] = line

                print('DNS.',line_to_remove - 4,' supprimé')        
        with open('ssl/extfile.cnf', 'w') as file:
            file.writelines(lines)

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

#------------Modification du ssl certificate----------
def ssl_modification(host_web):
    found = False
    if host_web not in open('ssl/extfile.cnf', 'r').read():
        with open('ssl/extfile.cnf', 'r') as file:
            lines = file.read()
            numberOfLines = len(lines.splitlines()) + 1
        with open('ssl/extfile.cnf', 'a') as extfile:
            extfile.write(f'\nDNS.{numberOfLines - 4} = {host_web}')
        found = True
    
    if found:
        directory = os.getcwd()
        openSSL_path = openssl_path()
        directory += '\\ssl'
        command= f'{openSSL_path}\\openssl.exe x509 -req -sha256 -days 365 -in cert.csr -CA ca.pem -CAkey ca-key.pem -out cert.pem -extfile extfile.cnf -CAcreateserial -passin pass:toto'

        try:
            subprocess.run(command, check=True)
            print('ssl cerfitication changed')
        except Exception as e:
            print(e,'----------------')

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

#------------Creation of the client context
def _context():
    context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context_client.load_cert_chain(certfile='ssl/cert.pem', keyfile='ssl/key.pem')
    context_client.load_verify_locations(cafile='ssl/ca.pem')
    context_client.minimum_version = ssl.TLSVersion.TLSv1_2
    context_client.check_hostname= False
    return context_client

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
                if 'longdogechallenge' in host_web or host_web == 'optical.toys' or host_web == 'paint.toys' and host_web != None:
                    message = _remove(message)
                    print('A client is connected')
                    print(host_web)
                    print(message)
                    
                    #---------Check ra efa anaty ssl certificate ilay domain; sinon ajouter-na--------
                    ssl_modification(host_web)

                    #---------Client context---------
                    context_client = _context()
                    with socket.create_connection((host_web, 443)) as web:
                        with context_web.wrap_socket(web, server_hostname=host_web) as secure_web:
                            _client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                            client_socket = context_client.wrap_socket(_client_socket, server_side=True, do_handshake_on_connect=False)
                            try:
                                print('Performing handshake')
                                client_socket.do_handshake()
                                print('Handshake done')
                            except Exception as e:
                                print(e)
                                print('Handshake failed')   
                            
                            data = client_socket.recv(4096)
                            secure_web.sendall(data)
                            x = 0
                            while True:
                                try:
                                    response = secure_web.recv(4096)
                                    if response:
                                        print(response)
                                    x += 1
                                    if x > 2 : break
                                    client_socket.sendall(response)
                                except Exception as e:
                                    print(e, '\nNo data sent by the web server')
                                    break
                            suppression_doublon(str(host_web))
                            client_socket.close()
                            secure_web.close()
            _client_socket.close()  
        except ConnectionError:
            print('Connection error')
        finally:
            # _client_socket.shutdown(socket.SHUT_RDWR)
            _client_socket.close()  


#-------------Starting proxy------------------
def start():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        server.bind((host,port))
        server.listen(1)
        # secure_server = context_server.wrap_socket(server, server_side=True)
        # secure_server.bind((host,port))
        # secure_server.listen(5)
        print('[SERVER]  The server is on...')
        
        while True:
            try:
                _client_socket, client_addr = server.accept()
                signal.signal(signal.SIGINT, signal_handler)
                threading.Thread(target=request, args=(_client_socket,), daemon=True).start()
            except ConnectionResetError:
                print("[ERROR] Connection reset")
            except OSError as e :
                raise
            except Exception as e:
                print(e)
            except KeyboardInterrupt:
                print('[SERVER] The server is stopping...')
                exit(0)

start()