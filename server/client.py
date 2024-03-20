import socket
import ssl

#host = 'localhost'
host = '127.0.0.1'
port = 8081

def start():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket :
        client_socket.connect((host,port))
        # context = ssl.create_default_context()
        # client_socket = context.wrap_socket(client_socket, server_hostname= 'example.com')
        client_socket.sendall(b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n')
        while True:  
                response = client_socket.recv(1024)
                print(response.decode('utf-8'))
            

if __name__ == '__main__':
    start()
