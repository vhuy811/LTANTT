import threading


class ConnectionManager:
    """Quản lý danh sách client: socket -> {username, encryption_key}.

    Dùng threading.Lock để an toàn khi nhiều luồng (mỗi client một luồng) cùng
    truy cập danh sách.
    """

    def __init__(self):
        self.clients = {}            # socket -> dict {username, encryption_key}
        self.lock = threading.Lock()

    def add_client(self, client_sock, username, encryption_key):
        with self.lock:
            self.clients[client_sock] = {'username': username,
                                         'encryption_key': encryption_key}

    def remove_client(self, client_sock):
        with self.lock:
            if client_sock in self.clients:
                del self.clients[client_sock]

    def get_client(self, client_sock):
        with self.lock:
            return self.clients.get(client_sock)

    def broadcast(self, message, sender_sock):
        with self.lock:
            for client in self.clients:
                if client != sender_sock:
                    try:
                        client.send(message)
                    except Exception:
                        pass
