import sys
import time
import signal
import socket
from threading import Thread
from bbs import blum_blum_shub
from dh import generate_dh_parameters, get_private_key, get_public_key, get_shared_key
from sdes import encrypt_sdes, decrypt_sdes
import tkinter as tk
from tkinter import scrolledtext

COMMAND_CONNECT = 1
COMMAND_DISCONNECT = 2
COMMAND_MESSAGE = 3
BUFFER = 2048

SOCKET = None
THREAD_RECEIVE = None
THREAD_QUIT = False
KEYS = {}
PARAMS = None
PUBLIC_KEY = None
PRIVATE_KEY = None
CURRENT_USER = None

def terminate():
    global SOCKET, THREAD_RECEIVE, THREAD_QUIT
    if SOCKET:
        SOCKET.close()
    SOCKET = None
    THREAD_QUIT = True
    if THREAD_RECEIVE:
        THREAD_RECEIVE.join()
    THREAD_RECEIVE = None

def signal_handler(sig, frame):
    terminate()
    sys.exit(0)

def receive():
    global SOCKET
    try:
        return SOCKET.recv(BUFFER).decode('ascii').split(',')
    except:
        return None

def receive_async():
    global THREAD_QUIT, SOCKET, KEYS, PARAMS
    while not THREAD_QUIT and SOCKET:
        msg = receive()
        if not msg:
            continue        
        try:
            cmd, user = int(msg[0]), str(msg[1]).lower()
            if cmd == COMMAND_DISCONNECT:
                if user in KEYS:
                    del KEYS[user]
                add_message("{} left the chat.".format(user.capitalize()))
            elif cmd == COMMAND_CONNECT:
                for clients in msg[1:]:
                    user, key = clients.split(':')[0].lower(), clients.split(':')[1]
                    KEYS[user] = int(key)
                    add_message("{} joined the chat.".format(user.capitalize()))
            elif cmd == COMMAND_MESSAGE:
                if user in KEYS:
                    q, a = PARAMS
                    shared = get_shared_key(KEYS[user], PRIVATE_KEY, q)
                    secret = blum_blum_shub(10, shared)
                    add_message("From {}: {}".format(user.capitalize(), decrypt_sdes(msg[2], secret)))
        except Exception as e:
            print(e)
            THREAD_QUIT = True

def connect(nickname, server_port):
    global SOCKET, THREAD_RECEIVE, THREAD_QUIT, KEYS, PARAMS, PUBLIC_KEY, PRIVATE_KEY, CURRENT_USER
    try:
        port = int(server_port)
        SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        SOCKET.connect(('localhost', port))
        msg = receive()
        PARAMS = (int(msg[0]), int(msg[1]))
        q, a = PARAMS
        
        PRIVATE_KEY = get_private_key(q)
        PUBLIC_KEY = get_public_key(PRIVATE_KEY, q, a)
        CURRENT_USER = nickname
        add_message("Your public key is {}, and your private key is {}".format(PUBLIC_KEY, PRIVATE_KEY))
        SOCKET.sendall("{},{}".format(nickname, str(PUBLIC_KEY)).encode('ascii'))

        THREAD_RECEIVE = Thread(target=receive_async)
        THREAD_RECEIVE.start()

        add_message("Connected to the chat server.")
    except Exception as e:
        add_message("Error: {}".format(e))

def send_message(to_user, message):
    global SOCKET, KEYS, PRIVATE_KEY, PARAMS
    if not to_user or not message:
        add_message("Please enter recipient and message.")
        return

    if to_user not in KEYS:
        add_message("User {} not found in chat.".format(to_user))
        return

    shared = get_shared_key(KEYS[to_user], PRIVATE_KEY, PARAMS[0])
    secret = blum_blum_shub(10, shared)
    SOCKET.sendall("{},{}".format(to_user, encrypt_sdes(message, secret)).encode('ascii'))
    add_message("To {}: {}".format(to_user.capitalize(), message))

def add_message(msg):
    text_area.config(state=tk.NORMAL)
    text_area.insert(tk.END, msg + '\n')
    text_area.config(state=tk.DISABLED)
    text_area.yview(tk.END)

def on_closing():
    terminate()
    root.quit()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    root = tk.Tk()
    root.title("Secure Chat Client")

    frame_top = tk.Frame(root)
    frame_top.pack(pady=10)

    label_nick = tk.Label(frame_top, text="Nickname:")
    label_nick.pack(side=tk.LEFT)
    entry_nick = tk.Entry(frame_top)
    entry_nick.pack(side=tk.LEFT)

    label_port = tk.Label(frame_top, text="Server Port:")
    label_port.pack(side=tk.LEFT)
    entry_port = tk.Entry(frame_top)
    entry_port.pack(side=tk.LEFT)

    button_connect = tk.Button(frame_top, text="Connect", command=lambda: connect(entry_nick.get(), entry_port.get()))
    button_connect.pack(side=tk.LEFT)

    text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED)
    text_area.pack(padx=10, pady=10)

    frame_bottom = tk.Frame(root)
    frame_bottom.pack(pady=10)

    label_to_user = tk.Label(frame_bottom, text="To User:")
    label_to_user.pack(side=tk.LEFT)
    entry_to_user = tk.Entry(frame_bottom)
    entry_to_user.pack(side=tk.LEFT, padx=5)

    label_message = tk.Label(frame_bottom, text="Message:")
    label_message.pack(side=tk.LEFT)
    entry_message = tk.Entry(frame_bottom, width=50)
    entry_message.pack(side=tk.LEFT)

    button_send = tk.Button(frame_bottom, text="Send", command=lambda: send_message(entry_to_user.get(), entry_message.get()))
    button_send.pack(side=tk.LEFT)

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
