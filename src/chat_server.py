import sys
import signal
import time
import select
import socket
from sdes import encrypt_sdes, decrypt_sdes
from bbs import blum_blum_shub
from dh import generate_dh_parameters, get_private_key, get_public_key, get_shared_key
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread

COMMAND_CONNECT = 1
COMMAND_DISCONNECT = 2
COMMAND_MESSAGE = 3
BUFFER = 2048

SOCKET = None
CONNECTIONS = None
PUBLIC_KEYS = {}
PARAMS = None

def terminate():
    global SOCKET, CONNECTIONS
    if CONNECTIONS:
        for s in CONNECTIONS:
            s.close()
        CONNECTIONS.clear()
    SOCKET = None

def signal_handler(sig, frame):
    terminate()
    sys.exit(0)

def broadcast(text, excluded=None):
    if CONNECTIONS is None:
        return None

    text = text.encode('ascii')
    for s in CONNECTIONS:
        if s == SOCKET or s == excluded:
            continue
        try:
            s.sendall(text)
        except:
            s.close()
            CONNECTIONS.remove(s)

def server_loop():
    global SOCKET, CONNECTIONS, PUBLIC_KEYS, PARAMS
    while SOCKET:
        available_sockets, _, _ = select.select(CONNECTIONS, [], [])
        for s in available_sockets:
            if s == SOCKET:
                conn, addr = SOCKET.accept()
                CONNECTIONS.append(conn)
                conn.sendall("{},{}".format(PARAMS[0], PARAMS[1]).encode('ascii'))
                data = conn.recv(BUFFER)
                if data:
                    v = data.decode('ascii').lower().split(',')
                    PUBLIC_KEYS[conn] = {'nick': v[0], 'key': v[1]}
                    broadcast("{},{}:{}".format(COMMAND_CONNECT, v[0], v[1]), conn)
                    add_message("{} has joined the chat!".format(v[0].capitalize()))
                    if len(PUBLIC_KEYS.keys()) > 1:
                        conn.sendall("{},{}".format(COMMAND_CONNECT, ",".join(["{}:{}".format(x['nick'], x['key']) for o, x in PUBLIC_KEYS.items() if o != conn])).encode('ascii'))
            else:
                try:
                    data = s.recv(BUFFER)
                    if data:
                        data = data.decode('ascii').split(',')
                        if data and len(data) == 2:
                            to_user, from_user, msg = data[0], PUBLIC_KEYS[s]['nick'], data[1]
                            for o, v in PUBLIC_KEYS.items():
                                if v['nick'] == to_user:
                                    add_message("From {} to {}, MSG -> '{}'.".format(from_user.capitalize(), to_user.capitalize(), decrypt_sdes(msg, int(v['key']))))
                                    o.sendall("{},{},{}".format(COMMAND_MESSAGE, from_user, msg).encode('ascii'))
                                    break
                    else:
                        s.close()
                        if s in CONNECTIONS:
                            CONNECTIONS.remove(s)
                        if s in PUBLIC_KEYS:
                            add_message("{} has left the chat!".format(PUBLIC_KEYS[s]['nick'].capitalize()))
                            broadcast("{},{}".format(COMMAND_DISCONNECT, PUBLIC_KEYS[s]['nick']))
                            del PUBLIC_KEYS[s]
                except:
                    s.close()
                    if s in CONNECTIONS:
                        CONNECTIONS.remove(s)
                    if s in PUBLIC_KEYS:
                        add_message("{} has left the chat!".format(PUBLIC_KEYS[s]['nick'].capitalize()))
                        broadcast("{},{}".format(COMMAND_DISCONNECT, PUBLIC_KEYS[s]['nick']))
                        del PUBLIC_KEYS[s]

def add_message(msg):
    text_area.config(state=tk.NORMAL)
    text_area.insert(tk.END, msg + '\n')
    text_area.config(state=tk.DISABLED)
    text_area.yview(tk.END)

def start_server():
    global SOCKET, CONNECTIONS, PARAMS
    try:
        port = int(entry_port.get())
        CONNECTIONS = []
        PUBLIC_KEYS = {}
        SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        SOCKET.bind(('localhost', port))
        SOCKET.listen(10)
        CONNECTIONS.append(SOCKET)
        PARAMS = generate_dh_parameters()
        
        add_message('Starting Secure Chat Server -> localhost:{}.'.format(port))
        add_message('Session uses DH parameters, q={} and a={}.\n'.format(PARAMS[0], PARAMS[1]))

        thread_server = Thread(target=server_loop)
        thread_server.start()
    except Exception as e:
        add_message("Error: {}".format(e))

def on_closing():
    terminate()
    root.quit()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    root = tk.Tk()
    root.title("Secure Chat Server")

    frame_top = tk.Frame(root)
    frame_top.pack(pady=10)

    label_port = tk.Label(frame_top, text="Port:")
    label_port.pack(side=tk.LEFT)
    entry_port = tk.Entry(frame_top)
    entry_port.pack(side=tk.LEFT)

    button_start = tk.Button(frame_top, text="Start Server", command=start_server)
    button_start.pack(side=tk.LEFT)

    text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED)
    text_area.pack(padx=10, pady=10)

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
