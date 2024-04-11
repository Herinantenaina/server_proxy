# import socket 
# import threading


# host = '127.0.0.1'
# port = 8080

# #traitement des clients 
# def handle_client(server,client_socket):
#     #attente d'inputs from client
#     while True:
#         request_unsplit = client_socket.recv(4096).decode()
#         request_split = request_unsplit.split("\n")
#         first_line = request_split[0]
#         method,request,_ = first_line.split()

#         if not request:
#             break

#     print(f"Request: {request}")
#     print("[DISCONNETED] The client is disconnected")    
#     client_socket.close()


# #Reception de data          
# def start_server(): 
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((host,port))
#     server.listen(5)
#     print("The server is on...")
#     print("[WAITING] Waiting for a client...")
#     while True:
#         client_socket, client_addr = server.accept()
#         print(f"Client is connected [{client_addr[0]}:{port}]")
#         try:
#             threading.Thread(target=handle_client, args=(server,client_socket)).start()
#             # handle_client(server,client_socket)
#         except ConnectionResetError:
#             print("[DISCONNETED] The client is disconnected")


# #-----------Mila asina fonction arreter ilay  serveur fa miodia fotsiny ao---------

# if __name__ == "__main__":
#     start_server()
 
# import requests

# response = requests.get('https://www.example.com')
# print(f'Status code: {response.status_code}')
# print(f'Content: {response.text}')

# from flask import Flask, redirect, url_for

# app = Flask(__name__)

# @app.route('/redirect')
# def redirect_to_example_com():
#     return redirect(url_for('example.com'), code=301)

# @app.route('/external-website')
# def external_website():
#     return 'You have been redirected to the external website.'

# if __name__ == '__main__':
#     app.run()

# from http.server import HTTPServer, BaseHTTPRequestHandler

# class Serv(BaseHTTPRequestHandler):
#     def do_GET(self):
#         if self.path=='/':
#             self.path='/index.html'
#         try:
#             file_to_open=open(self.path[1:]).read()
#             self.send_response(200)
#         except:
#             file_to_open='file not found'
#             self.send_response(404)
#         self.end_headers()
#         self.wfile.write(bytes(file_to_open,'utf-8'))

# httpd=HTTPServer(('192.168.1.158',8081),Serv)
# httpd.serve_forever()  

# import socket
# import select
# import threading

# SOCKS_VERSION = 5

# class Proxy:
#     def __init__(self):
#         self.username = "username"
#         self.password = "password"
    
#     def run(self, host, port):
#         server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         server.bind((host,port))
#         server.listen(10)
#         while True:
#             conn, addr = server.accept()
#             print("New connection from {}".format(addr))
#             t = threading.Thread(target=self.handle_client, args=(conn,))
#             t.start()

#     def handle_client(self, connection):
#         #greating header
#         #read and unpack 2 bytes from client
#         version, nmethod = connection.recv(2)

# if __name__ == "__main__":
#     proxy = Proxy()
#     proxy.run("127.0.0.1", 8080)

# import socket
# import threading
# import select



# SOCKS_VERSION = 5


# class Proxy:
#     def __init__(self):
#         self.username = "username"
#         self.password = "password"

#     def handle_client(self, connection):
#         # greeting header
#         # read and unpack 2 bytes from a client
#         version, nmethods = connection.recv(2)

#         # get available methods [0, 1, 2]
#         methods = self.get_available_methods(nmethods, connection)

#         # accept only USERNAME/PASSWORD auth
#         if 2 not in set(methods):
#             # close connection
#             connection.close()
#             return

#         # send welcome message
#         connection.sendall(bytes([SOCKS_VERSION, 2]))

#         if not self.verify_credentials(connection):
#             return

#         # request (version=5)
#         version, cmd, _, address_type = connection.recv(4)

#         if address_type == 1:  # IPv4
#             address = socket.inet_ntoa(connection.recv(4))
#         elif address_type == 3:  # Domain name
#             domain_length = connection.recv(1)[0]
#             address = connection.recv(domain_length)
#             address = socket.gethostbyname(address)

#         # convert bytes to unsigned short array
#         port = int.from_bytes(connection.recv(2), 'big', signed=False)

#         try:
#             if cmd == 1:  # CONNECT
#                 remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#                 remote.connect((address, port))
#                 bind_address = remote.getsockname()
#                 print("* Connected to {} {}".format(address, port))
#             else:
#                 connection.close()

#             addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
#             port = bind_address[1]

#             reply = b''.join([
#                 SOCKS_VERSION.to_bytes(1, 'big'),
#                 int(0).to_bytes(1, 'big'),
#                 int(0).to_bytes(1, 'big'),
#                 int(1).to_bytes(1, 'big'),
#                 addr.to_bytes(4, 'big'),
#                 port.to_bytes(2, 'big')
#             ])
#         except Exception as e:
#             # return connection refused error
#             reply = self.generate_failed_reply(address_type, 5)

#         connection.sendall(reply)

#         # establish data exchange
#         if reply[1] == 0 and cmd == 1:
#             self.exchange_loop(connection, remote)

#         connection.close()


#     def exchange_loop(self, client, remote):
#         while True:
#             # wait until client or remote is available for read
#             r, w, e = select.select([client, remote], [], [])

#             if client in r:
#                 data = client.recv(4096)
#                 if remote.send(data) <= 0:
#                     break

#             if remote in r:
#                 data = remote.recv(4096)
#                 if client.send(data) <= 0:
#                     break


#     def generate_failed_reply(self, address_type, error_number):
#         return b''.join([
#             SOCKS_VERSION.to_bytes(1, 'big'),
#             error_number.to_bytes(1, 'big'),
#             int(0).to_bytes(1, 'big'),
#             address_type.to_bytes(1, 'big'),
#             int(0).to_bytes(4, 'big'),
#             int(0).to_bytes(4, 'big')
#         ])


#     def verify_credentials(self, connection):
#         version = ord(connection.recv(1)) # should be 1

#         username_len = ord(connection.recv(1))
#         username = connection.recv(username_len).decode('utf-8')

#         password_len = ord(connection.recv(1))
#         password = connection.recv(password_len).decode('utf-8')

#         if username == self.username and password == self.password:
#             # success, status = 0
#             response = bytes([version, 0])
#             connection.sendall(response)
#             return True

#         # failure, status != 0
#         response = bytes([version, 0xFF])
#         connection.sendall(response)
#         connection.close()
#         return False


#     def get_available_methods(self, nmethods, connection):
#         methods = []
#         for i in range(nmethods):
#             methods.append(ord(connection.recv(1)))
#         return methods

#     def run(self, host, port):
#         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         s.bind((host, port))
#         s.listen()

#         print("* Socks5 proxy server is running on {}:{}".format(host, port))

#         while True:
#             conn, addr = s.accept()
#             print("* new connection from {}".format(addr))
#             t = threading.Thread(target=self.handle_client, args=(conn,))
#             t.start()


# if __name__ == "__main__":
#     proxy = Proxy()
#     proxy.run("127.0.0.1", 3000)


# import socket

# import threading

# def handle_client_request(client_socket):

#     print("Received request:\n")

#     # read the data sent by the client in the request

#     request = b''

#     client_socket.setblocking(False)

#     while True:

#         try:

#             # receive data from web server

#             data = client_socket.recv(1024)

#             request = request + data

#             # Receive data from the original destination server

#             print(f"{data.decode('utf-8')}")

#         except:

#             break

#     # extract the webserver's host and port from the request

#     host, port = extract_host_port_from_request(request)

#     # create a socket to connect to the original destination server

#     destination_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#     # connect to the destination server

#     destination_socket.connect((host, port))

#     # send the original request

#     destination_socket.sendall(request)

#     # read the data received from the server

#     # once chunk at a time and send it to the client

#     print("Received response:\n")

#     while True:

#         # receive data from web server

#         data = destination_socket.recv(1024)

#         # Receive data from the original destination server

#         print(f"{data.decode('utf-8')}")

#         # no more data to send

#         if len(data) > 0:

#             # send back to the client

#             client_socket.sendall(data)

#         else:

#             break

#     # close the sockets

#     destination_socket.close()

#     client_socket.close()

# def extract_host_port_from_request(request):

#     # get the value after the "Host:" string

#     host_string_start = request.find(b'Host: ') + len(b'Host: ')

#     host_string_end = request.find(b'\r\n', host_string_start)

#     host_string = request[host_string_start:host_string_end].decode('utf-8')

#     webserver_pos = host_string.find("/")

#     if webserver_pos == -1:

#         webserver_pos = len(host_string)

#     # if there is a specific port

#     port_pos = host_string.find(":")

#     # no port specified

#     if port_pos == -1 or webserver_pos < port_pos:

#         # default port

#         port = 80

#         host = host_string[:webserver_pos]

#     else:

#         # extract the specific port from the host string

#         port = int((host_string[(port_pos + 1):])[:webserver_pos - port_pos - 1])

#         host = host_string[:port_pos]

#     return host, port

# def start_proxy_server():

#     port = 8080

#     # bind the proxy server to a specific address and port

#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#     server.bind(('127.0.0.1', port))

#     # accept up to 10 simultaneous connections

#     server.listen(10)

#     print(f"Proxy server listening on port {port}...")

#     # listen for incoming requests

#     while True:

#         client_socket, addr = server.accept()

#         print(f"Accepted connection from {addr[0]}:{addr[1]}")

#         # create a thread to handle the client request

#         client_handler = threading.Thread(target=handle_client_request, args=(client_socket,))

#         client_handler.start()

# if __name__ == "__main__":

#     start_proxy_server()

# import socket

# hostname = 'www.example.com\r'
# ip = socket.gethostbyname(hostname)

# print(f'The host name is: {hostname}, its IP is: {ip}')

# import socket

# url = "xxxx www.youtube.com"
# url = url.split(' ')
# url = url[1]
# url = url.strip('\r')
# val = socket.gethostbyname(url)
# print(val)

# import requests
# import socket

# # Set up the proxy server information
# proxy_ip = socket.gethostbyname()
# proxy_port = 8080

# # Set up the proxy dictionary
# proxyDict = {  "http"  :  "http://" + proxy_ip + ":" + str(proxy_port), 
#                "https" :  "http://" + proxy_ip + ":" + str(proxy_port),  }

# # Use the proxy server to connect to a website server
# response = requests.get('https://example.com', proxies=proxyDict)

# # Print the response
# print(response.text)

# import socket

# val = "HTTP/1.1\r\nHost:www.google.com:443\r\nProxy-Connection:"
# check = '\\'
# val= val.split('\r\n')
# x = val[1].split(':4')[0]
# val = val[0] + r'\r\n' + x + r'\r\n\r\n'
# print(val)

# input = 'HTTP/1.1\\r\\nHost:mobile.events.data.microsoft.com:443\\r\\nProxy-Connection:'
# val = "HTTP/1.1\r\nHost:www.google.com:443\r\nProxy-Connection:"

# check = "\\"

# if check in val :
#     print("GG")
# else: 
#     print("Not GG")

# val = 'ajifv,pkr\\v sd;l'
# val = val.split('v')
# val = val[0] + r'\r\n' + val[1] +  r'\r\n'
# print(val)

# import socket

# request = "CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com\r\n\r\n"

# client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client_socket.connect(("www.example.com", 443))
# client_socket.send(request.encode("utf-8"))

# response = b""
# while True:
#     data = client_socket.recv(4096)
#     if not data:
#         break
#     response += data

# print(response.decode("utf-8"))

# client_socket.close()


# t = 'tay'     
# t = b'' + t.encode()
# print(t)

# x = ['afva', 'bvanjo' ,'cavbrzk', 'dacezp']
# t = b'GET http://mid.gov.mg/ HTTP/1.1\r\nHost: mid.gov.mg\r\nProxy-Connection: keep-alive\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: fr,fr-FR;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6\r\n\r\n'  
# t = t.decode('utf-8')

# tab = t.split(' ')
# tab[1] = '/'
# tab = ' '.join(tab)
# print(tab)

# import requests

# url = 'https://example.com'
# response = requests.get(url)

# # Check the response status code
# if response.status_code == 200:
#     # Process the response content
#     print(response.content)
# else:
#     # Handle the error
#     print(f"Error {response.status_code}: {response.reason}")

# import socket
# import ssl

# url = "https://example.com"  # replace with the URL you want to request
# host, port = url[8:].split(":")  # extract the host and port from the URL

# # create a socket and establish a connection
# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# sock.connect((host, int(port) if port else 443))

# # create an SSL context and wrap the socket with it
# context = ssl.create_default_context()
# context.check_hostname = False  # disable hostname verification
# context.verify_mode = ssl.CERT_NONE  # disable certificate verification
# ssl_sock = context.wrap_socket(sock, server_hostname=host)

# # send an HTTP GET request
# request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
# ssl_sock.sendall(request.encode())

# # receive the HTTP response
# response = b""
# while True:
#     data = ssl_sock.recv(1024)
#     if not data:
#         break
#     response += data

# # print the response content
# print(response.decode())

# # close the connection
# ssl_sock.close()

# import sys
# import os

# print(os.path.dirname(sys.executable))

# import certifi
# import requests

# cafile = certifi.where()
# response = requests.get('https://hostinger.co.id', verify=cafile)
# print(response.content)

# import ssl 

# print(ssl.PROTOCOL_TLS)

# host_web = 'example.com'
# host_web = 'https://' + host_web
# print(host_web)

# x = 'gijvkpz'
# x = x.encode()
# x= b'' +  x
# print(x)

# import socket
# import ssl 

# mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# mysocket.connect(("example.com", 80))
# mysocket.sendall(b'CONNECT / HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0\r\n\r\n')
# s = mysocket.recv(1024)
# print(s.decode())

# while True:
#     data = mysocket.recv(512)
#     if len(data) < 1 :
#         break
#     print(data)
# mysocket.close()

# import requests

# s = requests.get('https://example.com')
# print(s.headers)

# import socket

# def simple_http_server(host='127.0.0.1', port=8080):
#     # Create a new socket object
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#         # Bind the socket to the address and port
#         s.bind((host, port))
#         # Listen for incoming connections
#         s.listen()
#         print(f'Server listening on {host}:{port}')
#         # Accept a connection
#         conn, addr = s.accept()
#         with conn:
#             print('Connected by', addr)
#             # Set the HTML response
#             html_response = '<html><body><h1>Hello, World!</h1></body></html>'
#             # Send the HTTP response header
#             header = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n'.format(len(html_response))
#             # Send the header and HTML content
#             conn.sendall(header.encode('utf-8'))
#             # Send a blank line between the header and content
#             conn.sendall(b'\r\n')
#             # Send the HTML content
#             conn.sendall(html_response.encode('utf-8'))

# # Call the function to start the server
# try:
#     simple_http_server()
# except Exception as e:
#     print(e)

# import socket
# import ssl

# def check_ssl_certificate(ip_address, port):
#     context = ssl.create_default_context()
#     context.check_hostname = True
#     context.verify_mode = ssl.CERT_REQUIRED

#     try:
#         sock = socket.create_connection((ip_address, port))
#         wrapped_sock = context.wrap_socket(sock, server_hostname=ip_address)
#         wrapped_sock.connect((ip_address, port))

#         cert = wrapped_sock.getpeercert()
#         print(f"Subject: {cert['subject']}")
#         print(f"Issuer: {cert['issuer']}")
#         print(f"Expiration: {cert['notAfter'].decode('ascii')}")

#         # Additional checks
#         # Verify that the certificate is issued by a trusted CA
#         # Verify that the certificate's domain matches the IP address or hostname

#     except Exception as e:
#         print(f"Error checking SSL certificate: {e}")

# # Example usage
# check_ssl_certificate('127.0.0.1', 8080)  # Replace with your desired IP address and port



# -------------------------------------------------------------------
# -------Using request to send the server reponse to the client------
# -------------------------------------------------------------------
# import ssl
# import requests
# import threading
# import socket
# import errno
# import signal

# host ='localhost'
# port = 8080

# response = requests.get('http://example.com')
# response = 'e'.join(response.headers)
# print(response)

# def handle_client(client_socket):
#     while True:
#         if client_socket.fileno() != -1:  
#             print('A client is connected')
#             while True:
#                 try:
#                     response = requests.get('http://example.com')
#                     client_socket.sendall(response.text.encode())
#                 except Exception as e :
#                     print(e,'---------------------')
#                     break
#                 finally:
#                     client_socket.close()
#         else:
#             break

# def signal_handler(server,signal, frame):
#     print('[SERVER] Stopping the server...')
#     server.close()

# def start():
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
#         server.bind((host,port))
#         server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
#         server.listen(1)
#         print('[SERVER]  The server is on...')
#         while True:
#             try:
#                 # global client_socket
#                 client_socket, client_addr = server.accept()
#                 # print(f"Client is connected at: {client_addr[0]}:{port}")
#                 threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start() 
#                 signal.signal(signal.SIGINT, signal_handler)
#             except ConnectionResetError:
#                 print("[ERROR] Connection reset")
#             except OSError as e :
#                 if e.errno != errno.EINTR:
#                     raise

# start()


# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as destination_server:
#             destination_server.connect((host_web, port_web))
#             destination_server.sendall(message)
            
#             while True:
#                 if port_web == 80: # HTTP
#                     server_response = destination_server.recv(1024)
#                     if len(server_response) > 0:
#                         client_socket.sendall(server_response)
#                     else:
#                         break 

#                 else: # HTTPS
#                     context = ssl.create_default_context(ssl.PROTOCOL_TLS_CLIENT)
#                     context.load_verify_locations(cafile='ssl/ca.pem')
#                     wrapped_client = context.wrap_socket(client_socket, server_side=True, do_handshake_on_connect=False)
#                     server_response = destination_server.recv(1024)
#                     if len(server_response) > 0:
#                         try:
#                             destination_server.getpeercert()
#                         except:
#                             print('Did not get the ssl certificate of the webserver')
#                         # server_response = server_response.replace(b'Connection: close', b'Connection: keep-alive')
#                         # wrapped_client.sendall(server_response)
#                         # wrapped_client.do_handshake()
#                         # wrapped_client.sendall(server_response)
#                     else:
#                         break

                    
#             destination_server.close()

# import socket
# import ssl
# import time
# import threading

# hostname = 'www.example.com'
# context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
# context.load_cert_chain(certfile='ssl/cert.pem', keyfile='ssl/key.pem')
# host = 'localhost'
# port = 8081
# # hostname_server = socket.getfqdn()

# def extract_port_host_method_request(message):
#     try:
#         message_ = _decode(message)
#         message_ = message_.split("\n")   

#                 #----Host_Web----
#         host_web = message_[1]
#         host_web = host_web.split(':')
#         host_web = host_web[1]
#         host_web = host_web.split(' ')
#         host_web = host_web[1]
#         host_web = host_web.strip('\r')
#         try:
#             ip_web = f"'{socket.gethostbyname(host_web)}'"
#         except:
#             print("Wrong domain name entered: [",host_web,"]" )     
    

#         return host_web
#     except:
#         return None
    
# #-------------Decoding the message since some have different format--------------    
# def _decode(message:any):
#     try:
#         message = message.decode('utf-8')
#         return message
#     except UnicodeDecodeError:
#         try:
#             message = message.decode('ISO-8859-1')
#             return message
#         except UnicodeDecodeError:
#             try:
#                 message = message.decode('Windows-1252')
#                 return message
#             except:
#                 return None 

# #-------------Remove the error int the request due to the domain being wronged-----------
# def _remove(message:bytes):
#     message = message.decode('utf-8')
#     message = message.split(' ')
#     message[1] = '/'
#     message = ' '.join(message)
#     message = b'' + message.encode()
#     return message


#------------Stopping the server manually-----------------
# def signal_handler(signal, frame):
#     print('[SERVER] Stopping the server...')
#     exit(0)


# def request(client_socket):
#     if client_socket.fileno() != -1:
#         while True:
#             try:
#                 message = client_socket.recv(1024)
#             except Exception as e:
#                 break

#             if not message:
#                 break
            
#             #------Obtention du port, du methode et de l'adresse host------
#             host_web=  extract_port_host_method_request(message)
#         print('A client is connected')
#         with socket.create_connection((hostname, 443)) as sock:
#             with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#                 ssock.send(b'GET / HTTP/1.1\r\nHost: ' + hostname.encode()+ b'\r\n\r\n')
#                 response = bytes()
#                 while True:
#                     try:
#                         data= ssock.recv(1024)
#                         if not data:
#                             break
#                         response += data
#                         client_socket.sendall(data)
#                         print(response)
#                     except Exception as e:
#                         print(e)
#                         break
#                     finally:
#                         sock.close()    


# #-------------Starting proxy------------------
# def start():
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
#         server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
#         server.bind((host,port))
#         server.listen(1)
#         print('[SERVER]  The server is on...')
#         while True:
#             try:
#                 client_socket, client_addr = server.accept()
#                 # client_socket = context.wrap_socket(client_socket, server_side=True)
#                 threading.Thread(target=request, args=(client_socket,), daemon=True).start()
#                 signal.signal(signal.SIGINT, signal_handler)
#             except ConnectionResetError:
#                 print("[ERROR] Connection reset")
#             except OSError as e :
#                 raise 
#             except KeyboardInterrupt:
#                 print('[SERVER] The server is stopping...')
#                 exit(0)


# start()

# import socket
# import ssl
# import time
# import certifi
# import os 

# # Context creation
# ssl_context = ssl.create_default_context()
# ssl_context.verify_mode = ssl.CERT_REQUIRED

# ssl_context.check_hostname = False

# # Create an SSLSocket
# client_socket = socket.socket()
# secure_client_socket = ssl_context.wrap_socket(client_socket, do_handshake_on_connect=False)

# ssl_context.load_verify_locations(cafile=os.path.abspath(certifi.where()), capath=None, cadata=None)
# # Only connect, no handshake
# t1 = time.time()
# retval = secure_client_socket.connect(("example.org", 443))
# print("Time taken to establish the connection: {:2.3f}".format(time.time() - t1))

# # Explicit handshake
# t3 = time.time()
# secure_client_socket.do_handshake()
# print("Time taken for SSL handshake: {:2.3f}".format(time.time() - t3))

# from urllib.request import urlopen
# urlopen('https://www.howsmyssl.com/a/check').read()

# import subprocess

# def ssl_modification(host_web):
#     openssl = 'openssl'
#     command = 'x509'
#     arguments = ['-req', '-sha256', '-days', '365', '-in', 'cert.csr', '-CA', 'ca.pem', '-CAkey', 'ca-key.pem', '-out', 'cert.pem', '-extfile', 'extfile.cnf', '-CAcreateserial']
#     directory = '/path/to/directory'
#     with open('extfile.cnf', 'r') as file:
#         for line in file:
#             if host_web in line: 
#                 pass
#             else: 
#                 with open('extfile.cnf', 'a') as extfile:
#                     extfile.write(f' SubjectAltName = DNS:{host_web}\t')

# import subprocess
# import os
# host_web = 'tay'
# def ssl_modification(host_web):
#     found = False
#     if host_web not in open('ssl/extfile.cnf', 'r').read():
#         with open('ssl/extfile.cnf', 'r') as file:
#             lines = file.read()
#             numberOfLines = len(lines.splitlines()) + 1
#         with open('ssl/extfile.cnf', 'a') as extfile:
#             extfile.write(f'\nDNS.{numberOfLines - 4} = {host_web}')
#         found = True
    
#     if found:
#         directory = os.getcwd()
#         directory += '\\ssl'
#         command= 'openssl x509 -req -sha256 -days 365 -in cert.csr -CA ca.pem -CAkey ca-key.pem -out cert.pem -extfile extfile.cnf -CAcreateserial -passin pass:toto'
#         try:
#             subprocess.run(command, cwd=directory, check=True)
#         except Exception as e:
#             print(e)

# ssl_modification(host_web)

# subjectAltName = @alt_names

# [alt_names]
# IP.1 = 127.0.0.1
# DNS.1 = example.com
# DNS.2 = youtube.com
# DNS.3 = facebook.web
# DNS.4 = facebook.com
# DNS.5 = hostinger.co.id
# DNS.5 = hostinger.co.id
# DNS.6 = tay

# import re

# string = "DNS.5 = hostinger.co.id"
# new_string = re.sub(r"^DNS\.\d+ = ", f"DNS.{4} = ", string)
# print(new_string)


# import subprocess
# import os

# def openssl_path():
#     for root, _, files in os.walk(os.environ["ProgramFiles"]):
#         if "openssl.exe" in files:
#             path = os.path.join(root, "openssl.exe")
#             path = path.split('\\openssl.exe')
#             path = path[0]
#             return path
            
#     raise FileNotFoundError("OpenSSL n'existe sur se système")

# def ssl_modification(host_web):
#     found = False
#     if host_web not in open('ssl/extfile.cnf', 'r').read():
#         with open('ssl/extfile.cnf', 'r') as file:
#             lines = file.read()
#             numberOfLines = len(lines.splitlines()) + 1
#         with open('ssl/extfile.cnf', 'a') as extfile:
#             extfile.write(f'\nDNS.{numberOfLines - 4} = {host_web}')
#         found = True
    
#     if found:
#         directory = os.getcwd()
#         openSSL_path = openssl_path()
#         directory += '\\ssl'
#         command= f'{openSSL_path}\\openssl.exe x509 -req -sha256 -days 365 -in cert.csr -CA ca.pem -CAkey ca-key.pem -out cert.pem -extfile extfile.cnf -CAcreateserial -passin pass:toto'

#         try:
#             subprocess.run(command, check=True)
#             print('ssl cerfitication changed')
#         except Exception as e:
#             print(e,'----------------')

            
# ssl_modification("example.com")

# website = ['a', "b",'c',"d"]
# array = ' '.join(website) 
# print(array)
# if 'a.com' in array:
#     print('aaaaa')

# import socket, ssl
# import urllib.request

# # Create socket and context
# context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# context.load_verify_locations(cafile='ca.pem')
# # context.verify_mode = ssl.CERT_REQUIRED
# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# wrapped_socket = context.wrap_socket(sock,)

# # Bind to the address and port
# wrapped_socket.bind(('127.0.0.1', 443))

# # Start listening for connections
# wrapped_socket.listen(5)

# # Wait for a connection
# connection, address = wrapped_socket.accept()

# # Handle the request and download the content
# request = urllib.request.Request('https://www.example.com/')
# response = urllib.request.urlopen(request)
# content = response.read()

# # Close the connection
# connection.close()

# import ssl
# import socket
# import urllib.request

# # Create an SSL context
# context = ssl.create_default_context()

# # Configure the proxy settings
# proxy_host = 'your-proxy-host'
# proxy_port = 8080

# # Create a proxy handler
# proxy_handler = urllib.request.ProxyHandler({'https': f'http://{proxy_host}:{proxy_port}'})

# # Create a new SSL context with the proxy handler
# opener = urllib.request.build_opener(proxy_handler)
# urllib.request.install_opener(opener)

# # Make an HTTPS request with the SSL context
# request = urllib.request.Request('https://example.com/', headers={'User-Agent': 'Mozilla/5.0'})
# response = urllib.request.urlopen(request, context=context)

# # Read the response and print the content type
# content_type = response.getheader('Content-Type')
# print(content_type)

# # Read the response and print the content
# content = response.read()
# print(content)

# def _remove(message:bytes, host_web):
#     message = message.decode('utf-8')
#     message = message.split(' ')
#     message[0] = 'GET'
#     if host_web in message[1]:
#         message[1] = '/'
#     message = ' '.join(message)
#     message = b'' + message.encode()
#     return message

# message = b'GET paint.toys:443 HTTP/1.1\r\nHost: paint.toys\r\nConnection: keep-alive\r\nsec-ch-ua: "Microsoft Edge";v="123", "Not:A-Brand";v="8", "Chromium";v="123"\r\nIf-None-Match: "6dc6511cb97cef93f2d5ef2984e90385-ssl"\r\nsec-ch-ua-mobile: ?0\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0\r\nsec-ch-ua-platform: "Windows"\r\nAccept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: no-cors\r\nSec-Fetch-Dest: image\r\nReferer: https://paint.toys/\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: fr,fr-FR;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6\r\nCookie: _ga=GA1.1.1790861145.1712129439; usprivacy=1---; ad_clicker=false; GLAM-AID=4515a323471a425588855a9570898284; _cc_id=1142981ba082cac72ca0520330ec886f; _sharedid=98d63405-2305-4d6f-b911-102b45a5ba4f; _sharedid_cst=zix7LPQsHA%3D%3D; panoramaId=ebe4a83dc940ac22ec292f19a807185ca02c16c4c9d5af8b4ccc85391d8bb246; panoramaId_expiry=1712734326096; _awl=2.1712144925.5-4b6c8c6dd44b8e241c0114905f7535df-6763652d6575726f70652d7765737431-0; GLAM-JID=c1e67b6bc77346caa27ade4a24f19025; GLAM-SID=fdc116e58da04e8099ebaa66673fe166; __j_state=%7B%22landing_url%22%3A%22https%3A%2F%2Fpaint.toys%2F%22%2C%22pageViews%22%3A1%2C%22prevPvid%22%3A%225c82c690e6644ae0a0da5803fe26f39c%22%2C%22extreferer%22%3A%22https%3A%2F%2Fpaint.toys%2F%22%2C%22user_worth%22%3A0%7D; FCNEC=%5B%5B%22AKsRol-QzpXGqXrd8hQH7TVZiMPkRKj8Nnbhnezg0Dm5yTkEYz0zpVYP7vs-bJ2wWBlbrSq9G9xh8wKg-xjEtjsLcbGn4_fFhQIZJzDMNZ6oYd7dSMvcvI1YnbAczgAjdJJZyK30wp24gtJHnO-2F6vnMnj6HeQ7Jg%3D%3D%22%5D%5D; __gads=ID=36d42ffe93ec799e:T=1712129519:RT=1712144927:S=ALNI_MblNSV4pMkDSQyQ-QBXE8uSpwY9tA; __gpi=UID=00000d54d4bde55a:T=1712129519:RT=1712144927:S=ALNI_MYc7aHYYlxl0-KSJkBrsABsIi-cxQ; __eoi=ID=82ae7cbe1c1a8473:T=1712129519:RT=1712144927:S=AA-AfjZJBa9kbBm4BXAGAeLxAw11; _ga_VJBRK9986D=GS1.1.1712144926.3.1.1712145456.0.0.0; _ga_CEFZJ359V8=GS1.1.1712144926.3.1.1712145456.0.0.0\r\n\r\n'
# message = _remove(message, 'paint.toys')
# print(message)

# t = b''
# if not t:
#     print('Ok')

# import socket
# import ssl
# import certifi
# context_web = ssl.create_default_context()
# context_web.load_verify_locations('ca.pem', certifi.where())
# host_web = 'example.com'

# # with socket.create_connection((host_web, 443)) as web:
# #                         with context_web.wrap_socket(web, server_hostname=host_web) as secure_web:
# #                                 x = secure_web.getpeercert()
# #                                
# #                                 print(x)

# x = {'subject': ((('countryName', 'US'),), (('stateOrProvinceName', 'California'),), (('localityName', 'Los Angeles'),), (('organizationName', 'Internet\xa0Corporation\xa0for\xa0Assigned\xa0Names\xa0and\xa0Numbers'),), (('commonName', 'www.example.org'),)), 'issuer': ((('countryName', 'US'),), (('organizationName', 'DigiCert Inc'),), (('commonName', 'DigiCert Global G2 TLS RSA SHA256 2020 CA1'),)), 'version': 3, 'serialNumber': '075BCEF30689C8ADDF13E51AF4AFE187', 'notBefore': 'Jan 30 00:00:00 2024 GMT', 'notAfter': 'Mar  1 23:59:59 2025 GMT', 'subjectAltName': (('DNS', 'www.example.org'), ('DNS', 'example.net'), ('DNS', 'example.edu'), ('DNS', 'example.com'), ('DNS', 'example.org'), ('DNS', 'www.example.com'), ('DNS', 'www.example.edu'), ('DNS', 'www.example.net')), 'OCSP': ('http://ocsp.digicert.com',), 'caIssuers': ('http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt',), 'crlDistributionPoints': ('http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl', 'http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl')}
# x = ' '.join(x)
# print(x)

# x = b'HTTP/1.1 304 Not Modified\r\nCache-Control: public,max-age=0,must-revalidate\r\nCache-Status: "Netlify Edge"; hit\r\nDate: Thu, 04 Apr 2024 08:59:18 GMT\r\nEtag: "4701cff42682639e223fc5ddf38be898-ssl-df"\r\nServer: Netlify\r\nStrict-Transport-Security: max-age=31536000\r\nVary: Accept-Encoding\r\nX-Nf-Request-Id: 01HTM5AZBFDWQMFBR4BHVXKVPG\r\n\r\n'
# x = x.decode('utf-8')
# x = x.split(' ')
# print(x[1])

# ilport brotli

# fragment = b'HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nAge: 80345\r\nCache-Control: public,max-age=0,must-revalidate\r\nCache-Status: "Netlify Edge"; hit\r\nContent-Encoding: br\r\nContent-Length: 1430\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Tue, 09 Apr 2024 05:34:55 GMT\r\nEtag: "be020b0561a1977792a110c7e406cdaf-ssl-df"\r\nServer: Netlify\r\nStrict-Transport-Security: max-age=31536000\r\nVary: Accept-Encoding\r\nX-Nf-Request-Id: 01HV0NMACW4TG7C5R7VR8T226A\r\n\r\n\xa0)\x01\x80\xfc\xafS\x9b\xede\xfa\xa7+\xb8\xa2\xb4\x06\xa9n\x15R*O\xc07\xc6\x14)H>R\xd7\xab\xd3t\xcbz\xd3\x18?\xda/%e\xe2\xa2t\xac}\x03\xffh\xefBX@\x9c\x99\xdd\x02\xa1"\xf0\x80\x92\x8d\xacq\xa9\x91u\xb6\xcaT\xd8\x9a\x0cg3}\xa5\x90F\xe1`^\x02\x02F\xcd\xa2\xd6\xa0\xa4\x03\r\x82)1\x8b\x00\x0f\x0c\x19\x02X2\xe9-\xed9\xc2\xb9DQ\xee\x82Kt_J\xacU\xcc\x07\x1d/\x194\xecc/\xe5Tz\x00H\x82fa\xc2 \x1ec3\xb0\xb9\xd4\xcf\x8e"\x92\xf0+X\x1ccp=V\x03]\xb1o4\x0c\xf3x\x82\xf4_\x02\xb2\xf0\xde\xe9,\x14\x01\x9b\xc8\xc4\x8a~$J\x0b|c\xa9\xae\xeb\xf0\x80\x8e\xbd A\x90<ACaBk\x99}X\x87\xb2\xfb\x08\xccf\xe8)0\x14E\xec\xc7\xd4\x1c\xc1\xe5\x19\xfa5H\xb9\x9bK\x84gn\x97\x16\xb2\x05\x9e\xd2\x00\x1b\x8cJ0q\xeb\x13o\xc7P\x15\xaa\xe7Gj\xf4\xfeBz?9"Q\xa4d_\xfc\xeae\x16\xef\x96\xcc\x95\x12\xb5\xe2\x9c\x9a\xa3\x9839\xba\x0fj)&\x03)(b\x8f\x00\x17\xc7Qa+\xee\x9a\xb7\xa5/{\x04L\xbav\xb1\x94\n\xe2\xe7j\x08\xd5g\x81$\x83\x90u\x91\n\x93??\t\xcf|i_Q`\xc9\xb9\\4\xf98p\xb1Pe\xc6i\xd2x\x97\x17\x85i\xd6\x03\x1e\xd5G\xce\x97^\xcd\xceC\xa50\xdbptH\xd5\xdf\xd8\xab\xb8\xecR*\x95\xa6C\x9a\x1b\x8a|\xbc*\x89\xc3\xe8\x8a\xc1\xd7\xe1?\xfb\x10Wj\x7f\t\xbe\x11\xc8F6\xf8\x97\xf6d\xe69\x08k\x8c9H\x00R\x1f\xd03\x96\x88\xc6\x83R\xb8\x91\xced\xbd\x8f\xfe\xb8\xc4\xec\x94*0\x8bfs\x0c\xdd\xcaL\x8f\x85\x97\xda\t\xde\xdd\xc6\x0e\x94z~\xaa\xbf\xa6\xc5\xda \xc4T\xf1\x0f\x18\xf8\x81\x9d\xed5\xba\xbd\xb1\xb2\xbeBi\xb7\x9c\x869h\n\xb3\x82T<n\xe1\x88\xbcu\xbc\xd1\x9a\xa2M\xf9\x13;>\x18\xa0i\xba\xc7S\x8f\xa9\xd2\x19S\xa8\xa7</\x95\xcb\xfb\x85\xe9A\x9d\x0f\xf4\xd93f\xd2\x99d{\xb6\xc5\xee\n\x14\x0bJP\xca\xc4\xdb\x1b@\xd8\tJex\x85r\x13\x00$\x19|T\xad\xb4\xe5\xe7\xa8\xf7\x7f\xb1\xfaPI[H\xad\x06)\xe6\xc0\xbeg\x9d\xf3'
# rest= b"\xb0\x8e\x00\x11\x7f\xa2U_Y\xbd\xb2\xec\x9d\x8bvo\xa2\xd5\xe0\x154\xd8\xb2\x85#X\x80\x8e:\x92\x86\xa4\xce\x0b\xef\x84,\x9bM\r=\x9c\xa3\xd5\x92\xc9\x16\xe0\xc5N8\xfa\xf5\xff\x04s\xbb\xaf\xe2\xda\x1e+A\xd6$,\xf3DN\xe8k{F\xb3\xc5:\xef\xff\x1f\xb7\xecZ\xfc\xfd\xf98L#\xc806\x88\xc8\x10t\xe5\xee\xe2\x800\xd9v\xc6S%\xf5\x00f\xf5\x8e\x10@\x95\x8c\xd9\xaaH$z\\\x9c\x004\x81' v\xe9[P\x1a!\xfd\xe0a\xfc\xc8~,\xa1#|\xe7\x19\xd9\x9b\xf3 F&By\x04\xc6d\xc0\xf6\x05\xa3\xcb%\xce"
# add  = b'\xc2\xb4j\xc5\xcc\xfd\x86\xdd6\x182g"\xfaC6L%\xa2\xa8\xb6\xcb\x03;\xe8\xbbM"d\xe4`\x8e\x01M\xc0\xd0c\x8b\xb7\xb6\x8f{\r\x184\xfa\x11v\xe2\xf0\x1a k\xe0\xce\x1d\x151\xed\x11\x1c\xe3c\xcd\xb4\xf7\xbayn5\xfa\r\xcbB\xe0v\xb9\xc7\x86y\xd98\xb1:6\xd9\x01\x1b\x07l\x9a\xdf2\x96e\xfb\xdd\x18\xcc\x84\xff=\x88\x98\xe3~\xe3\xd8jt.F\xbe\xc5\x99\x17\xd2\xf9&\xffm\xba\xd5\xc4\x05~\xf8]\xd2\xfee\x1a*i\xfa>\x04\xb7g(#\xc5\x05\xb5\x11\xf1\xa8\xba\x87\xdb\x84\x81W:L\xcd\xda\xc4\x8a \x82\xf37\xd5E^\xf7QF\x06)\xc2\x18~X\xe4\x84_\xd0w\x8f\xd5\x8ct\x1d\xf9\x87Vq\xd63\xecc\xbb-\x87q=\xcau\x81\xaf3|\xd0\xb8"/g\xbeo\xb3\xa0\xc4\xcc1\xe5x1\tQ\xa4\x1c\x05\xca\x91\xd73{\x1d\xf7\t\xfaN\x86\x9e\xd2H_\xc2\xdd\xd0\xe5\xd7/\x90\xfa\xff\x0c\xd0\x9f\xa2\xa7tR\xb4\x8fx\xb2u\\\x89n4\x8dX\xa7\x8bs,4\xa3W\x85i\x10Av:w\xa5\r\xd96\xab6\xa8\x8d\xdf\x8e\x98Sd\xfeH\x19\x80C\xc3\x9aBO\x18\x90\x9b\xadXF;\x9e\xd6\x18\xc7\x1ct\x1a\xa1\xc3\x0e\x99i\xd8\x03\x03\x98\x89\x1e\xea\x8d>\x8b\xf6\x8b\xd7\xc9\x1a\xe4\x08s\x96\x1e\x84&\xf4\xd1\x97\xa4\x9a\x82\xa1\x8e\x85\xe0s\x9a\xfa\xf8v}N\x02\x99tA\x13\xe2\x8d\xa3\xf4|\x92\xb8\x8c\xe4H\xf1Pm\x07~T\xfaAEHxe-\x8f\x13\x96\xe2\xba\xbd\xcd\xff\xff\xc0\x0e\x13h\'CI\xf7\xc2\xc7\xdf\x1f\x04\xbc\xf5\x83\x1au\x81\xcf\xbd\rU\xa6\xf4\xcc\r\xbfZR\x9f"]m\x1ew\xc4\xa4o\xcd\xa6\xd1\xf5\xc8>=_\xb3\xd0\xc9/\x9e\xdd\xcb\xc7\x13e\xc5/\xf2\xac\xd9\x15n2\\\xf6\xbd\x9e\xbd%;\xd6\xee\xect\xb2\xd1;\xcfi\xfb\x03R\xc7\x92Y\x87\x83\xa8~z\xcb\x1c89\xe7\x80r\xebtp\xf5\xc7\xdf\x1f>B}\xf2.\x1a#P\x99m\x16\xe9\xab\x8f\x11s|\xc8\xfaM\xb5\x8f\x13\xdc\xeep\xc0,\x01V\x17\x99\xe1\xae$v\x85\xf0\xd5\x0bIQgH(\xc7\x8a\x1a\x0e#<\xbc\x99S,\x18\xba \xb6\x80C\xa6\xe9B\x0e=\xcd\xef\xfc\xb8\xbe\xbe\xb9\xbb\xb1\xb1\xb9\xb1[_\xa5\xfeP\xa1P(\x1c$\x1c>\xe8\xc6\x85\xaa\xba\x05\xab\x9b,\x95_!Yz/U\x04\xc3|\x16s\xf2\x12`\xdc\x918W9(\xe0\x9b-%4\x00-6J$\x96\xea\x0bY\x0e\xfe#\xa9\xbcy\xb5\xeag\x8d\xd3\xdeN\x7f:^\xbb\xd9X\xa4|\xf8\xa0\xeea\xd3W\xa9\xae\xb2H\xd50\x0b5\x19\x15\x05#b\x8d\xa2\x01\x03'
# length = 0

# def checking_content_length(fragment,first_fragment:bool):
#     if first_fragment:
#         try:
#             fragment.decode('utf-8')
#         except:
#             pos = fragment.find(b'\r\n\r\n')
#             not_ssl = fragment[0:pos]
#             length = len(fragment) - len(not_ssl) -4 
#         return length
#     else:
#         return len(fragment)

# i= 0
# content_length_reached = 0
# while True:
#     if i < 3:
#         if i == 0:
#             content_length_reached += checking_content_length(fragment,True)
#             print(i,' ', content_length_reached)
#             i += 1
#         if i == 1:
#             fragment = rest
#             content_length_reached += checking_content_length(fragment,False)
#             print(i,' ', content_length_reached)
#             i += 1
#         if i == 2:
#             fragment = add
#             content_length_reached += checking_content_length(fragment,False)
#             print(i,' ', content_length_reached)
#             i += 1
#     else: 
#         break

# print(content_length_reached)


# import os, subprocess


# def openssl_path():
#     for root, _, files in os.walk(os.environ["ProgramFiles"]):
#         if "openssl.exe" in files:
#             path = os.path.join(root, "openssl.exe")
#             path = path.split('\\openssl.exe')
#             return path[0]
            
#     raise FileNotFoundError("OpenSSL n'existe sur se système")


# directory = os.getcwd()
# openSSL_path = openssl_path()
# directory += '\\ssl'
# command= f'{openSSL_path}\\openssl.exe x509 -req -sha256 -days 365 -in cert.csr -CA ca.pem -CAkey ca-key.pem -out cert.pem -extfile extfile.cnf -CAcreateserial -passin pass:toto'


# subprocess.run(command, check=True)
# print('ssl cerfitication changed')

# string1 = "Hello"
# string2 = "World"

# # Compare the strings lexicographically
# print(sorted(string1, key=lambda x: x) < sorted(string2, key=lambda x: x))  # Output: True
a = b''
c = b''
i = 0
while i < 4:
    a += c
    i +=1
print(a)  