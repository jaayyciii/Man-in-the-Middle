#---------------------------------------------------------------------------------
#   Authors:        Niklas Philip Domingo
#                   Gillian Florin
#                   John Carlo Salinas
#   Course:         CPE 3252: Information Engineering
#   File Name:      client.py
#   Description:    a program for the client's end for a simple client-server
#                   application; compromised with a sniffer worm.
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
            run = False
    conn.close() 

def establishConnection():
    # instantiates a socket in the session layer
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect client to server 127.0.0.1 port 8000
    conn.connect(('127.0.0.1', 8000))
    print('SYSTEM: Server Connection Established')
    return conn

if __name__ == '__main__':
    conn = establishConnection()
    # receive message threading
    rcv = Thread(target=receiveMsg, args=(conn, ))
    rcv.start()
    # send message threading
    snd = Thread(target=sendMsg, args=(conn, ))
    snd.start()