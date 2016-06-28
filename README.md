## How to use
1.start server/venoms.py
2.set DESTINATION on client/client_config.py
(if server ip is 192.168.0.1 then sent DESTINATION = "192.168.0.1")
3.start client/xenophid.py
4.send commands from the server

###Commands
1. nomal shell commands - returns the output of the shell command
2. download directory_name - downloads the file if the file exists on the client using covert channel(using TCP source port)
3. upload directory_name - upload a file from server to client
4. inotify start - start tracking new file creation on the client and download the file
5. inotify stop - stop inotify function
6. dnspoof start SENDER_IP SENDER_MAC TARGET_IP ROUTER_IP DOMAIN - Starts arp spoofing to TARGET and ROUTER and show a fake website to the target on specified DOMAIN. Saves passwords sent with POST requests on the domain. The SENDER_IP and SENDER_MAC has to be the same as the client's IP and MAC addresses
7. dnspoof stop - stop dns spoofing and download the password file.
