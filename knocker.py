from scapy.all import *
from dcutils import parse_port_to_data



#this variable has to be length of 8
PORT_KNOCKER = [8000,7000,6000,5000,4000,3000,2000,1000]
PORT_KNOCKER_INDEX = 0
PORT_KNOCKER_TIME = 0
SOURCE_IP = 0
PASS = ""


def check_packet(pkt):
    global PORT_KNOCKER_INDEX
    global PORT_KNOCKER_TIME
    global SOURCE_IP
    #if it arrives within 2 second after the last packet arrival
    if time.time() - PORT_KNOCKER_TIME < 2:
        #if source IP is wron
        if SOURCE_IP != pkt["IP"].src:
            reset_port_knocker_variables()
            #if soruce IP is correct
        else:
            update_port_knocker_variables(pkt['UDP'].sport)
            #if it is the last port knocking packet
            if PORT_KNOCKER_INDEX >= len(PORT_KNOCKER):
                PORT_KNOCKER_INDEX = 0
	#if it does not arrive within 2 second after the last packet arrival
    else:
        reset_port_knocker_variables()

def update_port_knocker_variables(sport):
    global SOURCE_IP
    global PORT_KNOCKER_TIME
    global PORT_KNOCKER_INDEX
    global PASS
    PORT_KNOCKER_TIME = time.time()
    PORT_KNOCKER_INDEX += 1
    pass1, pass2 = parse_port_to_data(sport)
    PASS += pass1 + pass2

def reset_port_knocker_variables():
    global PORT_KNOCKER_INDEX
    global PASS
    PORT_KNOCKER_INDEX = 0
    PASS = ""


def port_knock(pkt):
    global PORT_KNOCKER_INDEX
	#first packet arriving from client
    if PORT_KNOCKER_INDEX == 0 :
        global SOURCE_IP
        SOURCE_IP = pkt["IP"].src
        update_port_knocker_variables(pkt['UDP'].sport)
    #second to last packet arriving from client
    else:
        check_packet(pkt)
