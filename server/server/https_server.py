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
import sys
# from concurrent.futures import ThreadPoolExecutor

#----------Web context-----------
context_web = ssl.create_default_context()
context_web.load_verify_locations('ca.pem', certifi.where())


host = '127.0.0.1'
port = 443

# Liste des sites web
blocked = ['www.googletagmanager.com','ad-delivery.net','faucetfoot.com','merequartz.com','track.offercheck24.com','securepubads.g.doubleclick.net' ,'adsense.google.com', 'www.media.net', 'advertising.amazon.com', 'www.taboola.com', 'www.outbrain.com',]

#--------Pour éviter l'ecriture simultanée d'un fichier par les differents thread
file_lock = threading.Lock()

#-------------Ajout python dans path-----------
python_exe = sys.executable
python_path = os.path.dirname(python_exe)
os.environ['PATH'] += os.pathsep + python_path 

#-------------Recherche du openssl.exe------------
def openssl_path():
    for root, _, files in os.walk(os.environ["ProgramFiles"]):
        if "openssl.exe" in files:
            path = os.path.join(root, "openssl.exe")
            path = path.split('\\openssl.exe')
            return path[0]
            
    raise FileNotFoundError("OpenSSL n'existe pas sur se système")

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

#---Création du ssl certificate et ajout du site web ---
#---si le website n'est pas encore enregistré dans le certificat---
def ssl_modification(site_web):
    with file_lock:
        found = False
        if site_web not in open('extfile.cnf', 'r').read():
            with open('extfile.cnf', 'r') as extfile:
                lines = extfile.read()
                numberOfLines = len(lines.splitlines()) + 1
            with open('extfile.cnf', 'a') as extfile:
                extfile.write(f'\nDNS.{numberOfLines - 4} = {site_web}')
            found = True
        
        if found:
            directory = os.getcwd()
            openSSL_path = openssl_path()
            directory += '\\ssl'
            command= f'{openSSL_path}\\openssl.exe x509 -req -sha256 -days 365 -in cert.csr -CA ca.pem -CAkey ca-key.pem -out cert.pem -extfile extfile.cnf -CAcreateserial -passin pass:toto'

            try:
                subprocess.run(command, check=True)
                print('Changement du certificat effectué')
            except Exception as e:
                print('[ERREUR LORS DU MODIFICATION DU SSL CERTIFICAT]',e)

#------------Arrêt du serveur manuellement-----------------
def signal_handler(signal, frame):
    print('[SERVER] Stopping the server...')
    exit(0)

#------------Créatin du context client-------------
def _context():
    context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context_client.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
    context_client.load_verify_locations(cafile='ca.pem')
    context_client.minimum_version = ssl.TLSVersion.TLSv1_2
    context_client.check_hostname= False
    context_client.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:AES-CBC:')
    return context_client

#---------Extraction du header et le corps de la page--------
def header_body(fragment:bytes):
    pos = fragment.find(b'\r\n\r\n')
    header = fragment[:pos + 4]
    fragment = fragment[pos + 4:]
    return header, fragment

#---------Pour bloquer les requêtes ne provenant pas de l'utilisateur--------
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
        print('[ERREUR] La requête provient pas d"un utilisateur',e)
        return False 
    
#--------Modification du header pour plus de sécurité------
def set_security(fragment:bytes) -> bytes:
    if b'X-Frame-Options:' not in fragment:
        pos = fragment.find(b'\r\n', fragment.find(b'\r\n', fragment.find(b'\r\n') +1) + 1)
        fragment = fragment[:pos] + b'\r\nX-Frame-Options: DENY' + fragment[pos:]
    else:
        fragment = fragment.decode('utf-8')
        start = 'X-Frame-Options:'
        end = '\r\n'
        pattern = rf"{re.escape(start)}(.*?)({re.escape(end)})"
        fragment = re.sub(pattern, rf"{start} DENY {end}", fragment)
        fragment = fragment.encode()

    if b'X-Content-Type-Options:' not in fragment:
        pos = fragment.find(b'\r\n', fragment.find(b'\r\n', fragment.find(b'\r\n', fragment.find(b'\r\n') +1) +1) + 1)
        fragment = fragment[:pos] + b'\r\nX-Content-Type-Options: nosniff' + fragment[pos:]
    else:
        fragment = fragment.decode('utf-8')
        start = 'X-Content-Type-Options:'
        end = '\r\n'
        pattern = rf"{re.escape(start)}(.*?)({re.escape(end)})"
        fragment = re.sub(pattern, rf"{start} nosniff {end}", fragment)
        fragment = fragment.encode()

    if b'X-XSS-Protection:' not in fragment:
       pos = fragment.find(b'\r\n', fragment.find(b'\r\n', fragment.find(b'\r\n', fragment.find(b'\r\n', fragment.find(b'\r\n') +1) +1) +1) + 1)
       fragment = fragment[:pos] + b'\r\nX-XSS-Protection: 1; mode=block' + fragment[pos:]
    else:
        fragment = fragment.decode('utf-8')
        start = 'X-XSS-Protection:'
        end = '\r\n'
        pattern = rf"{re.escape(start)}(.*?)({re.escape(end)})"
        fragment = re.sub(pattern, rf"{start}  1; mode=block {end}", fragment)
        fragment = fragment.encode()
    return fragment

#----------------------------------
#---------Client handler-----------
#----------------------------------
def request(_client_socket:socket, website):
    if _client_socket.fileno() != -1:
            try:
                while True:
                    try:
                        message = _client_socket.recv(1024)
                    except ConnectionError:
                        print("[ERREUR DE CONNEXION LORS DE LA RECEPTION DE L'HTTP REQUEST]")
                    except Exception as e:
                        print("[ERREUR LORS DE LA RECEPTION DE L'HTTP REQUEST] ",e)
    
                    #------Si message vide------
                    if not message or len(message) <= 0:
                        break
                
                    #------Obtention du nom du site web------
                    host_web =  extract_port_host_method_request(message)

                    # Filtre
                    if str(host_web) not in blocked and host_web != None and 'ads' not in str(host_web) and 'doubleclick' not in str(host_web):   
                    # if 'paint' in host_web: 
                        print('NetShield se connecte à', host_web)
                        
                        #---------Ajout du site web dans le certficat ssl si il n'y est pas--------
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
                                        
                                        #-----Négociation ssl/tsl-----
                                        if not handshake_done:
                                            try:
                                                client_socket.do_handshake()
                                                handshake_done = True
                                            except Exception as e:
                                                print('[Handshake failed]:',e,f'[{host_web}]')
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


                                secure_web.settimeout(10)
                                is_chunk = True
                                response = b''
                                header = b''
                                isBot = False
                                while True:
                                    # Réception des données chiffrées provenant du serveur web
                                    try:
                                        fragment = secure_web.recv(8192)
                                    except socket.timeout:
                                        break
                                    except Exception:
                                        print('[ERREUR LORS DE LA RECETPION DES DATA]',e)
                                        break
                                        
                                    #----- Si la response est vide ou rien est envoyé par le serveur web-----
                                    if fragment is None or len(fragment) == 0 or not fragment or fragment == b'':                              
                                        break

                                    #----Modification des headers--------
                                    if b'Content' in fragment or b'HTTP' in fragment :
                                        if b'chunked' not in fragment:
                                            is_chunk = False        
                                        header,fragment = header_body(fragment)
                                        if b'GET' in header:
                                            header = set_security(header)
                                        isBot = is_bot(header)
                                        fragment = header + fragment
                                        
        
                                    if isBot:#----si la requete est effectuée par un bot
                                        break    

                                    if not is_chunk:
                                        response += fragment

                                      
                                    #------------Envoi des data vers le client socket-------------                                    
                                    try:
                                        if not is_chunk:
                                            client_socket.sendall(fragment)
                                    
                                             
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


#-------------Serveur proxy------------------
def start(blocked):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        server.bind((host,port))
        server.listen(30)
        blocked = ' '.join(blocked) 
        print('[SERVEUR]  Le serveur est lancé...')
        
        while True: 
            try:
                _client_socket, client_addr = server.accept()
                signal.signal(signal.SIGINT, signal_handler)
                thread_ = threading.Thread(target=request, args=(_client_socket, blocked), daemon=False)
                thread_.start()                                      

            except ConnectionResetError:
                print("[ERROR] ERREUR DE CONNEXION")
                _client_socket.close()
            except OSError as e :
                _client_socket.close()
                raise
            except Exception as e:
                print('[EXCEPTION LORS DU DEMARAGE]',e)
                _client_socket.close()
            except KeyboardInterrupt:
                print('[SERVER] Arrêt du serveur...')
                _client_socket.close()
                exit(0)

#----------Lancement du seveur--------------
if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    start(blocked)