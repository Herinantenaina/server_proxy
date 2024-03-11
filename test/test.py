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

import socket
import ssl

def check_ssl_certificate(ip_address, port):
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        sock = socket.create_connection((ip_address, port))
        wrapped_sock = context.wrap_socket(sock, server_hostname=ip_address)
        wrapped_sock.connect((ip_address, port))

        cert = wrapped_sock.getpeercert()
        print(f"Subject: {cert['subject']}")
        print(f"Issuer: {cert['issuer']}")
        print(f"Expiration: {cert['notAfter'].decode('ascii')}")

        # Additional checks
        # Verify that the certificate is issued by a trusted CA
        # Verify that the certificate's domain matches the IP address or hostname

    except Exception as e:
        print(f"Error checking SSL certificate: {e}")

# Example usage
check_ssl_certificate('127.0.0.1', 8080)  # Replace with your desired IP address and port