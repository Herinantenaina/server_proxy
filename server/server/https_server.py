import socket
import ssl
import threading
import signal
import certifi
import subprocess
import os
import re
import time
# from concurrent.futures import ThreadPoolExecutor

#----------Web context-----------
context_web = ssl.create_default_context()
context_web.load_verify_locations('ca.pem', certifi.where())


host = '127.0.0.1'
port = 443

# Liste des sites web
website = ['cdn.intergient.com','font.googleapis.com','longdogechallenge.com', 'optical.toys', 'theuselessweb.com', 'paint.toys', 'example.com']
qwebsite = ['www.googletagmanager.com']
# hostname_server = socket.getfqdn()

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

#------------Modification du ssl certificate si le website n'est pas encore enregistré dans le certificat----------
def ssl_modification(host_web):
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
            print(e,'----------------')

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
        print('Voici le buffer qui derange: [',buffer,']')
        return 0

#----------To make the data to be sent in chunks---------
def adding_the_chunk_method(fragment:bytes):
    fragment = fragment.decode('utf-8')
    if 'chunked' not in fragment:
        pos = fragment.find('Content')
        x = 'Transfer-Encoding: chunked\r\n'
        fragment = fragment[:pos] + x + fragment[pos:]
    fragment = fragment.encode()
    return fragment

#---------Add X Content type options---------
def add_X_Content_Type_Options(frag: bytes) -> bytes:
    frag = frag.decode('utf-8')
    frag = frag.replace('chunked','chunked\r\nX-Content-Type-Options: nosniff')
    return frag.encode()
#----------Manala an ilay content length anaty https response-----------
def remove_content_length(fragment:bytes):
    try:
        fragment.find(b'Content-Length')
        fragment = fragment.split(b'\r\n')
        k = 0
        for content in fragment:
            if b'Content-Length' in content:
                del fragment[k]
            else:
                k += 1

        fragment = b'\r\n'.join(fragment)
        return fragment

    except Exception as e:
        return fragment

#---------Maka ab ilay header sy ilay data am ilay fragment indrindra--------
def header_body(fragment:bytes):
    pos = fragment.find(b'\r\n\r\n')
    header = fragment[:pos + 4]
    fragment = fragment[pos + 4:]
    return header, fragment

#--------Chunking fragment----------
def chunking_the_fragment(fragment:bytes):
    fragmentLenght = (hex(len(fragment))[2:] + '\r\n').encode() # Protocol for using
    fragment = fragmentLenght + fragment + ('\r\n').encode()
    return fragment

#-------Check si l'https réponse sera chunked-----
def check_if_chunk_method(fragment):
    try: 
        pos = fragment.find(b'chunked')
        fragment = fragment[:pos +7]
        fragment = fragment.decode('utf-8')
        if 'chunked' in fragment:
            return True
        else:
            return False
    except:
        return False

#------Change the Connection: keep-alive to Connection: close---------
def close_connection(fragment:bytes):
    try:
        header = fragment.decode('utf-8')
        header = header.replace('200', '202')
        if 'close' in header: 
            header = header.replace('keep-alive', 'close')
        else:
            x = header.find('\r\n')
            header = header[:x] + '\r\nConnection: close' + header[x:]
        header = header.encode()
        return header
    except UnicodeDecodeError:
        return fragment

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
                        print("ERREUR DE CONNEXION LORS DE LA RECEPTION DE L'HTTP REQUEST")
                        _client_socket.close()
                        break
                    except Exception as e:
                        print("ERREUR LORS DE LA RECEPTION DE L'HTTP REQUEST")
                        _client_socket.close()
                        break
                    #------Si message vide------
                    if not message:
                        _client_socket.close()
                        break
                
                    #------Obtention du port, du methode et de l'adresse host------
                    host_web =  extract_port_host_method_request(message)
                    if str(host_web) in website and host_web != None:
                        print('A client is connected')
                        print(host_web)

                        #---------Check ra efa anaty ssl certificate ilay domain; sinon ajouter-na--------
                        ssl_modification(host_web)

                        #---------Client context---------
                        context_client = _context()
                        with socket.create_connection((host_web, 443)) as web:
                            with context_web.wrap_socket(web, server_hostname=host_web) as secure_web:
                                _client_socket.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
                                client_socket = context_client.wrap_socket(_client_socket, server_side=True, do_handshake_on_connect=False)
                    
                                # -----------------------------
                                try:#------Ito ilay véritable https request------
                                    data = client_socket.recv(1024)
                                    # data = close_connection(data)
                                except Exception as e:
                                    print("ERREUR LORS DE LA RECEPTION DE L'HTTPS REQUEST")
                                    client_socket.shutdown(socket.SHUT_WR)  
                                    client_socket.close()
                                    secure_web.close()
                                    break

                                if data == b'' or not data or data == None or len(data) <= 0:
                                    client_socket.shutdown(socket.SHUT_WR)  
                                    client_socket.close()
                                    secure_web.close()
                                    break
                                print('HTTPS request:\n',data)

                                #-----Handshake-----
                                try:
                                    t1 = time.time()
                                    print('Performing handshake')
                                    client_socket.do_handshake()
                                    print("Handshake done in {:2.3f}".format(time.time() - t1))
                                except Exception as e:
                                    print(e)
                                    print('Handshake failed: ',host_web)
                                    _client_socket.close()
                                    secure_web.close()
                                    break
                                    
                                secure_web.sendall(data)

                                secure_web.settimeout(5)
                                t0 = time.time()
                                total_content_length = 0
                                actual_content_length = 0
                                is_chunk = False
                                first_fragment = True
                                while True:
                                    # Receive the encrypted data from the web server
                                    try:
                                        fragment = secure_web.recv(9000)
                                    except socket.timeout:
                                        client_socket.send(f"0\r\n\r\r\n\n".encode())
                                        print(f'-----{host_web}------\n',    f"b'0\r\n\r\n'")
                                        client_socket.send(b'')
                                        print('Timeout')
                                        client_socket.shutdown(socket.SHUT_WR)  
                                        client_socket.close()
                                        secure_web.close()
                                        break
                                    except Exception as e:
                                        print('[ERREUR LORS DE LA RECEPTION DES DATA DU WEBSITE] ',e)
                                        client_socket.shutdown(socket.SHUT_WR)  
                                        secure_web.close()
                                        client_socket.close()
                                        break

                
                                    if len(fragment) == 0 or not fragment or fragment == b'':#----- Si response est vide-----
                                        print(f'Réponse vide[{host_web}]')
                                        if is_chunk:
                                            fragment = f"0\r\n\r\n".encode() # Last chunk to be sent so the browser knows that there will be no more chunk after this
                                            client_socket.sendall(fragment)  
                                        client_socket.send(b'')
                                        client_socket.shutdown(socket.SHUT_WR)                                     
                                        client_socket.close()
                                        secure_web.close()
                                        break
                                    

                                    if total_content_length == 0:#-----fragment voalohany indrindra-------
                                        is_chunk = check_if_chunk_method(fragment)
                                        total_content_length = content_length_ssl_data(fragment)    
                                        fragment = remove_content_length(fragment)       
                                        header,fragment = header_body(fragment)
                                        header = adding_the_chunk_method(header)
                                        header = add_X_Content_Type_Options(header)
                                        print(f'{host_web}\n{header}')
                                        client_socket.sendall(header)
                                        # time.sleep(0.5)
                                    


                                    #------------Sending the data to the client socket(browser)-------------
                                    try:
                                        if not is_chunk:
                                            print('Modified')
                                            fragment = chunking_the_fragment(fragment)# encode the fragment to be chunked
                                        else:
                                            print('Not modified')

                                        print(f'-----------{host_web}--------------\n',fragment,'\n',"Response sent in {:2.3f}".format(time.time() - t0))
                                        client_socket.sendall(fragment)
                                    except ConnectionError:
                                        print('Connection error ---------------------')
                                    except Exception as e:
                                        print(f'------{e}:{host_web}+++++++') 


                                                     
                                     #-------------Hi check ra efa tratra ilay content_lenght----------
                                    actual_content_length += actual_contentLenght(fragment, first_fragment)
                                    print(f'------{host_web}-----',actual_content_length,'=>', total_content_length)
                                    first_fragment = False
                                    if actual_content_length >= total_content_length:
                                        fragment = f'0\r\n\r\n'.encode() # Last chunk to be sent so the browser knows that there will be no more chunk after this
                                        print('-------------------------\n',fragment)
                                        client_socket.sendall(fragment)
                                        client_socket.send(b'')
                                        print('Last chunk sent')
                                        client_socket.close()
                                        secure_web.close()
                                        break
                                    
                                print(f'-----{host_web}------\n''Total temps pris:{:2.3f}'.format(time.time() - t0))
                                # if actual_content_length == 0:
                                #     client_socket.send(b'')   
                                suppression_doublon(str(host_web))
                                break
                
            except WindowsError:
                print('Windows error')
                try:
                    client_socket.shutdown(socket.SHUT_WR)
                except:
                    pass
                _client_socket.close()
            finally:
                try:
                    client_socket.shutdown(socket.SHUT_WR)
                except:
                    pass 
                _client_socket.close()
    else:
        try:
            client_socket.shutdown(socket.SHUT_WR)
        except:
            pass  
        _client_socket.close()


#-------------Starting proxy------------------
def start(website):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        server.bind((host,port))
        server.listen(1)
        website = ' '.join(website) 
        print('[SERVER]  The server is on...')
        
        while True: 
            try:
                _client_socket, client_addr = server.accept()
        
                signal.signal(signal.SIGINT, signal_handler)
                thread_ = threading.Thread(target=request, args=(_client_socket, website), daemon=False)
                thread_.start()
                # try:
                #     _client_socket.close()
                # except Exception as e :
                #     print('[EXCEPTION LORS DE LA FERMETURE DU SOCKET CLIIENT]',e)
                #     pass                                        

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
