#---------------------------------------------------------------------------------
#   Authors:        Niklas Philip Domingo
#                   Gillian Florin
#                   John Carlo Salinas
#   Course:         CPE 3252: Information Engineering
#   File Name:      server.py
#   Description:    a program for the server's end for a simple client-server
#                   application
#----------------------------------------------------------------------------------
import socket
from threading import Thread
run = True

def receiveMsg(conn):
    global run
    while run:
        try:
            # receive server data
            msg = conn.recv(1024)
            if not msg:
                continue
            print('\nServer: {}'.format(msg.decode()))

        # try catch exceptions
        except socket.error as err:
            run = False
        except KeyboardInterrupt:
            run = False
    conn.close()

def sendMsg(conn):
    global run
    while run:
        try:
            # send messsage to connected client
            msg = input("Client: ")
            conn.sendall(msg.encode())
        # try catch exceptions
        except socket.error as err:
            run = False
        except KeyboardInterrupt:
            run 

def listenConnection():
    # instantiates a socket in the session layer
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # binds the socket to the address '127.0.0.1' and port 8000
    s.bind(('127.0.0.1', 8000))
    # listens for incomming connections; allow only 1 pending connection
    s.listen(1)
    # accept connection from client
    conn, addr = s.accept()
    print('SYSTEM: Client Connection Accepted')
    return conn, addr, s

if __name__ == '__main__':
    conn, addr, s = listenConnection()
    # receive message threading
    rcv = Thread(target=receiveMsg, args=(conn, ))
    rcv.start()
    # send message threading
    snd = Thread(target=sendMsg, args=(conn, ))
    snd.start()
