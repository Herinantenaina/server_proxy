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
website = ['longdogechallenge.com', 'optical.toys', 'theuselessweb.com', 'paint.toys', 'example.com']
qwebsite = ['www.youtube.com', 'github.com']
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
def data_sent_in_chunks(fragment:bytes):
    pos = fragment.find(b'Content')
    x = b'Transfer-Encoding: chunked\r\n'
    fragment = fragment[:pos] + x + fragment[pos:]
    return fragment

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
                        print("Connection error while receiving the client request")
                        _client_socket.close()
                        break
                    except Exception as e:
                        print(e)
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
                                _client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                                client_socket = context_client.wrap_socket(_client_socket, server_side=True, do_handshake_on_connect=False)
                    
                                # -----------------------------
                                try:#------Ito ilay véritable https request------
                                    data = client_socket.recv(1024)
                                    print('Ito ny HTTPS request:\n',data)
                                except Exception as e:
                                    print(e,'   Error while receiving the request')

                                if data == b'' or not data or data == None or len(data) <= 0:
                                    break

                                #-----Handshake-----
                                try:
                                    t1 = time.time()
                                    print('Performing handshake')
                                    client_socket.do_handshake()
                                    print("Handshake done in {:2.3f}".format(time.time() - t1))
                                except Exception as e:
                                    print(e)
                                    print('Handshake failed')
                                    _client_socket.close()
                                    secure_web.close()
                                    break
                                    
                                secure_web.sendall(data)

                                secure_web.settimeout(10)
                                t0 = time.time()
                                total_content_length = 0
                                actual_content_length = 0
                                first_fragment = True
                                while True:
                                    # Receive the encrypted data from the web server
                                    try:
                                        fragment = secure_web.recv(4096)
                                    except socket.timeout:
                                        print('Timeout')
                                        client_socket.close()
                                        secure_web.close()
                                        break
                                    except Exception as e:
                                        print(e,'++++++++++++++++++++++++++++++')
                                        secure_web.close()
                                        client_socket.close()
                                        break

                
                                    if len(fragment) == 0 or not fragment or fragment == b'':#----- Si response est vide-----
                                        fragment = b'0\r\n\r\n' # Last chunk to be sent so the browser knows that there will be no more chunk after this
                                        client_socket.sendall(fragment)                                        
                                        client_socket.close()
                                        secure_web.close()
                                        break
                                    

                                    if total_content_length == 0:#-----fragment voalohany indrindra-------
                                        total_content_length = content_length_ssl_data(fragment)    
                                        fragment = remove_content_length(fragment)
                                        fragment = data_sent_in_chunks(fragment)       
                                        header,fragment = header_body(fragment)
                                        print(header)
                                        client_socket.sendall(header)
                                        # time.sleep(0.5)
                                    


                                    #------------Sending the data to the client socket(browser)-------------
                                    try:
                                        fragment = chunking_the_fragment(fragment)# the transfer encoding: chunks
                                        print('-------------------------\n',fragment)
                                        client_socket.sendall(fragment)
                                        print("Response sent in {:2.3f}".format(time.time() - t0))
                                    except ConnectionError:
                                        print('Connection error ---------------------')
                                    except Exception as e:
                                        print(f'------{e}+++++++') 


                                                     
                                     #-------------Hi check ra efa tratra ilay content_lenght----------
                                    actual_content_length += actual_contentLenght(fragment, first_fragment)
                                    first_fragment = False
                                    if actual_content_length >= total_content_length:
                                        fragment = b'0\r\n\r\n' # Last chunk to be sent so the browser knows that there will be no more chunk after this
                                        print('-------------------------\n',fragment)
                                        client_socket.sendall(fragment)
                                        print('Last chunk sent')
                                        client_socket.close()
                                        secure_web.close()
                                        break
                                    
                                print('Ito ilay content length: ', actual_content_length)  
                                suppression_doublon(str(host_web))
                                break
                
            except WindowsError:
                print('Windows error')
                _client_socket.close()
            finally:
                _client_socket.close()
    else:
        _client_socket.close()


#-------------Starting proxy------------------
def start(website):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        server.bind((host,port))
        server.listen(10)
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
                print(e)
                _client_socket.close()
            except KeyboardInterrupt:
                print('[SERVER] The server is stopping...')
                _client_socket.close()
                exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    start(website)
