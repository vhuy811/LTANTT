import threading


class RoomManager:
    """Quản lý phòng chat: mỗi phòng là một tập socket; broadcast theo phòng."""

    def __init__(self):
        self.rooms = {}              # room_name -> set(client sockets)
        self.lock = threading.Lock()

    def create_room(self, room_name):
        with self.lock:
            if room_name not in self.rooms:
                self.rooms[room_name] = set()

    def join_room(self, room_name, client_sock):
        with self.lock:
            if room_name not in self.rooms:
                self.rooms[room_name] = set()
            self.rooms[room_name].add(client_sock)

    def leave_room(self, room_name, client_sock):
        with self.lock:
            if room_name in self.rooms:
                self.rooms[room_name].discard(client_sock)

    def broadcast_room(self, room_name, message, sender_sock):
        with self.lock:
            if room_name not in self.rooms:
                return
            for client in self.rooms[room_name]:
                if client != sender_sock:
                    try:
                        client.send(message)
                    except Exception:
                        pass
