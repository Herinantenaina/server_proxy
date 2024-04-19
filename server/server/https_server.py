import socket
import ssl
import threading
import signal
import certifi
import subprocess
import os
import re
import time
import json
# from concurrent.futures import ThreadPoolExecutor

#----------Web context-----------
context_web = ssl.create_default_context()
context_web.load_verify_locations('ca.pem', certifi.where())


host = '127.0.0.1'
port = 443

# Liste des sites web
qwebsite = ['font.googleapis.com','longdogechallenge.com', 'www.googletagmanager.com', 'optical.toys', 'theuselessweb.com', 'paint.toys', 'example.com', 'puginarug.com']
website = ['www.googletagmanager.com','securepubads.g.doubleclick.net' ,'adsense.google.com', 'www.media.net', 'advertising.amazon.com', 'www.taboola.com', 'www.outbrain.com',]

#--------Pour éviter l'ecriture simultanée d'un fichier par les differents thread
file_lock = threading.Lock()

#-------------Searching the openssl.exe directory------------
def openssl_path():
    for root, _, files in os.walk(os.environ["ProgramFiles"]):
        if "openssl.exe" in files:
            path = os.path.join(root, "openssl.exe")
            path = path.split('\\openssl.exe')
            return path[0]
            
    raise FileNotFoundError("OpenSSL n'existe sur se système")

def extract_port_host_method_request(message:bytes):
    try:
        message_ = message.decode('utf-8')
        message_ = message_.split("\n")   

                #----Host_Web----
        host_web = message_[1]
        host_web = host_web.split(':')
        host_web = host_web[1]
        host_web = host_web.split(' ')
        host_web = host_web[1]
        host_web = str(host_web.strip('\r'))
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
    with file_lock:
        if host_web in open('extfile.cnf', 'r').read():
            count = 0
            line_to_remove = 0
            numberOfLines  = 0
            lines = 0
            with open('extfile.cnf', 'r') as file:
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
            with open('extfile.cnf', 'w') as file:
                file.writelines(lines)

#-------------Modification du extfile pour le ssl certificat------------
def modification_du_derniere_ligne():
        with file_lock:
            with open('extfile.cnf', 'r') as file:
                lines = file.readlines()
                
            i = 1
            first_empty_line = True
            with open('extfile.cnf', 'w') as file:
                for line in lines:
                    line = line.encode()
                    if first_empty_line and line == b'\n':
                        file.write(line.decode('utf-8'))
                        first_empty_line = False
                    
                    if line != b'\n':
                        file.write(line.decode('utf-8'))
                        i += 1  

            k = 1
            with open('extfile.cnf', 'r') as file:
                lines = file.readlines()

            with open('extfile.cnf', 'w') as file:
                for line in lines:
                    line = line.encode()
                
                    if k == i:
                        if b'\n' in line:
                            line = line.replace(b'\n',b'')
                            file.write(line.decode('utf-8'))
                        else:
                            file.write(line.decode('utf-8'))
                    else:
                        file.write(line.decode('utf-8'))
                    k += 1

#------------Modification du ssl certificate si le website n'est pas encore enregistré dans le certificat----------
def ssl_modification(host_web):
    with file_lock:
        found = False
        if host_web not in open('extfile.cnf', 'r').read():
            with open('extfile.cnf', 'r') as extfile:
                lines = extfile.read()
                numberOfLines = len(lines.splitlines()) + 1
            with open('extfile.cnf', 'a') as extfile:
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
                print('[ERREUR LORS DU MODIFICATION DU SSL CERTIFICAT]',e)

#------------Stopping the server manually-----------------
def signal_handler(signal, frame):
    print('[SERVER] Stopping the server...')
    exit(0)

#------------Creation of the client context-------------
def _context():
    context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context_client.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
    context_client.load_verify_locations(cafile='ca.pem')
    context_client.minimum_version = ssl.TLSVersion.TLSv1_2
    context_client.check_hostname= False
    context_client.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:AES-CBC:')
    return context_client

#-------Maka content length à chaque sendall()--------
def actual_contentLenght(fragment:bytes,first_fragment:bool):
    if first_fragment:
        try:
            fragment.decode('utf-8')
            return 0
        except:
            pos = fragment.find(b'\r\n')
            not_ssl = fragment[0:pos]
            length = len(fragment) - len(not_ssl) - 4
 
        return length
    else:
        return len(fragment)
    
#-----------Mitady content_length an ilay encrypted data-------------
def content_length_ssl_data(fragment:bytes):
    position1 = fragment.find(b'Content-Length: ')
    position2 = fragment.find(b'Content-Type: ')
    if position1 > position2:
        position2 = position1 + position2
        position1 = position2 - position1
        position2 = position2 - position1 + 25
    buffer = fragment[position1:position2]
    buffer = buffer.decode('utf-8')
    buffer = buffer.split(' ')
    k = 0
    for content in buffer:
        k += 1
    buffer = buffer[k-1]
    try:
        return int(buffer)
    except:
        return 0

#---------Maka ab ilay header sy ilay data am ilay fragment indrindra--------
def header_body(fragment:bytes):
    pos = fragment.find(b'\r\n\r\n')
    header = fragment[:pos + 4]
    fragment = fragment[pos + 4:]
    return header, fragment

#---------Pour bloquer les bots--------
def is_bot(header:bytes) -> bool:
    try:
        header = header.decode('utf-8')
        header = header.split('\r\n')
        for content in header:
            if 'User-Agent' in content:
                user_agent = content
                user_agent = user_agent.replace('User-Agent: ', '')

                with open('user-agent.json', 'r') as file:
                    data = json.load(file)        

                for content in data:
                    if re.search(content['pattern'], user_agent):
                        return True
                    else: 
                        return False
            
            
    except Exception as e:
        print('[Bots erreur]',e)
        return False 
#----------------------------------
#---------Client handler-----------
#----------------------------------
def request(_client_socket:socket, website):
    if _client_socket.fileno() != -1:
        # _client_socket.setblocking(False)
            try:
                while True:
                    #---------Tokony asina set timeout eto--------
                    try:
                        message = _client_socket.recv(1024)
                    except ConnectionError:
                        print("[ERREUR DE CONNEXION LORS DE LA RECEPTION DE L'HTTP REQUEST]")
                    except Exception as e:
                        print("[ERREUR LORS DE LA RECEPTION DE L'HTTP REQUEST] ",e)
    
                    #------Si message vide------
                    if not message or len(message) <= 0:
                        break
                
                    #------Obtention du port, du methode et de l'adresse host------
                    host_web =  extract_port_host_method_request(message)
                    if str(host_web) not in website and host_web != None and 'ads' not in str(host_web):
                    #if 'you' in str(host_web):    
                        print('A client is connected:', host_web)
                       

                        #---------Check ra efa anaty ssl certificate ilay domain; sinon ajouter-na--------
                        ssl_modification(host_web)

                        #---------Client context---------
                        context_client = _context()
                        with socket.create_connection((host_web, 443)) as web:
                            with context_web.wrap_socket(web, server_hostname=host_web) as secure_web:
                                _client_socket.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
                                client_socket = context_client.wrap_socket(_client_socket, server_side=True, do_handshake_on_connect=False)
                    
                                # -----------------------------
                                request = b''
                                handshake_done = False
                                #------Maka an le https request ------
                                while True:
                                    try:
                                        data = client_socket.recv(1024)
                                        if data:
                                            request += data
                                        else :
                                            break

                                        if b'\r\n\r\n' in data:
                                            break
                                        
                                        #-----Handshake-----
                                        if not handshake_done:
                                            try:
                                                client_socket.do_handshake()
                                                handshake_done = True
                                            except Exception as e:
                                                print('[Handshake failed]:',e,f'[{host_web}]')
                                                secure_web.close()
                                                break
                                    except Exception as e:
                                        print("ERREUR LORS DE LA RECEPTION DE L'HTTPS REQUEST")
                                        secure_web.close()
                                        break
                                
                                try: #Check if the request is empty
                                    if request == b'' or not request or request == None or len(request) <= 0:
                                        client_socket.shutdown(socket.SHUT_WR)  
                                        client_socket.close()
                                        secure_web.close()
                                        break
                                except:
                                    break

                                #----Send request to the web server----- 
                                secure_web.sendall(request)


                                secure_web.settimeout(5)
                                t0 = time.time()
                                total_content_length = 0
                                length_header = 0
                                is_chunk = True
                                response = b''
                                header = b''
                                isBot = False
                                while True:
                                    # Receive the encrypted data from the web server
                                    try:
                                        fragment = secure_web.recv(8192)
                                    except socket.timeout:
                                        print('Timeout')
                                        break
                                    except Exception:
                                        print('[ERREUR LORS DE LA RECETPION DES DATA]',e)
                                        break
                                        

                                    if fragment is None or len(fragment) == 0 or not fragment or fragment == b'':#----- Si response est vide-----
                                        print(f'Réponse vide[{host_web}]')                                  
                                        break

                                    
                                    if b'Content' in fragment or b'HTTP' in fragment :#-----fragment voalohany indrindra-------
                                        if b'chunked' not in fragment:
                                            total_content_length = content_length_ssl_data(fragment) 
                                            is_chunk = False        
                                        header,fragment = header_body(fragment)
                                        isBot = is_bot(header)
                                        length_header = len(header)
                                        fragment = header + fragment
                                        
        
                                    if isBot:#----If bot is making the request but not a user
                                        break    

                                    if not is_chunk:
                                        response += fragment

                                      
                                    #------------Sending the data to the client socket(browser)-------------                                    
                                    try:
                                        if not is_chunk and len(response) >= total_content_length + length_header:
                                            response += (b'\r\n\r\n' )
                                            client_socket.sendall(response)
                                    
                                            break  
                                        elif is_chunk:
                                            client_socket.sendall(fragment)
                                            
                                    except ConnectionError as e:
                                        print('[Erreur de connexion]',e )
                                    except Exception as e:
                                        print(f'------{e}:{host_web}+++++++') 

                                web.close()
                                suppression_doublon(str(host_web))
                                modification_du_derniere_ligne()
                                
                    break
                
            except WindowsError as e:
                print('[Windows error]',e)
            finally: 
                _client_socket.close()
    else:
        _client_socket.close()


#-------------Starting proxy------------------
def start(website):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        server.bind((host,port))
        server.listen(30)
        website = ' '.join(website) 
        print('[SERVER]  The server is on...')
        
        while True: 
            try:
                _client_socket, client_addr = server.accept()
        
                signal.signal(signal.SIGINT, signal_handler)
                thread_ = threading.Thread(target=request, args=(_client_socket, website), daemon=False)
                thread_.start()                                      

            except ConnectionResetError:
                print("[ERROR] Connection reset")
                _client_socket.close()
            except OSError as e :
                _client_socket.close()
                raise
            except Exception as e:
                print('[EXCEPTION LORS DU DEMARAGE]',e)
                _client_socket.close()
            except KeyboardInterrupt:
                print('[SERVER] The server is stopping...')
                _client_socket.close()
                exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    start(website)
