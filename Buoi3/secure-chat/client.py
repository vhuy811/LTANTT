import socket
import ssl
import threading
import os
import binascii
from message_encryption import MessageEncryption

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8443

CA_CERT = 'certs/ca/ca.crt'
CLIENT_CERT = 'certs/client/client.crt'
CLIENT_KEY = 'certs/client/client.key'


def receive_messages(ssl_sock, me):
    try:
        while True:
            enc_data = ssl_sock.recv(4096)
            if not enc_data:
                break
            try:
                msg = me.decrypt(enc_data)
                print(msg)
            except Exception:
                print("[!] Failed to decrypt message")
    except Exception:
        pass


def main():
    username = input("Username: ").strip()
    # Sinh khoá AES-256 riêng cho client này
    aes_key = os.urandom(32)
    me = MessageEncryption(aes_key)

    # Nạp CA để XÁC MINH server; nạp cert/key client để server xác minh lại (TLS 2 chiều)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = context.wrap_socket(sock, server_hostname=SERVER_HOST)
    ssl_sock.connect((SERVER_HOST, SERVER_PORT))

    # Gửi username + khoá AES (hex) cho server
    ssl_sock.send(f"{username}:{binascii.hexlify(aes_key).decode()}".encode())

    threading.Thread(target=receive_messages, args=(ssl_sock, me), daemon=True).start()

    print("Type messages (type 'exit' to quit):")
    while True:
        msg = input()
        if msg.lower() == 'exit':
            break
        enc_msg = me.encrypt(msg)
        ssl_sock.send(enc_msg)

    ssl_sock.close()


if __name__ == '__main__':
    main()
