# import socket

# def start_client():
#     host = '127.0.0.1'  # Server's IP address
#     port = 8080          # Server's port

#     # Create a TCP socket
#     client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#     # Connect to the server
#     client_socket.connect((host, port))

#     # Send a message to the server
#     message = "Hello, server! This is the client."
#     client_socket.sendall(message.encode())

#     # Receive the server's response
#     response_data = client_socket.recv(1024)
#     print("Received from server:", response_data.decode())

#     # Close the connection
#     client_socket.close()

# if __name__ == '__main__':
#     start_client()

#----------bandy sur youtube miampy modif kely
# import socket
# host = '127.0.0.1'
# port = 9879
# buffer_size = 1024
# text = "Hello, World!"
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.connect((host, port))
# text = text.encode('utf-8')
# s.send(text)
# data = s.recv(buffer_size)
# s.close()
# print("received data:", data)

import socket

host = '127.0.0.1'
port = 8080
disconnect = 'Disconnected'

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host,port))
client.send(b'Hello server')
#mesg = client.recv(1024).decode()
#print("Ito le message le serveur: " ,mesg)
while True:
    msg = input("-->  ")
    if  msg:
        #envoi de l'input vers le serveur
        client.send(msg.encode())
        print("Here's ur message:", msg)
    else:
        break
    

print("Bye")
client.close()




