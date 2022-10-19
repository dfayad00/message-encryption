
import hashlib
import socket

from crypto import KeyManager, DES
from crypto import HMAC

class Server:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.addr, self.port))
        self.s.listen(1)
        self.conn, self.addr = self.s.accept()

    def send(self, msg_bytes: bytes):
        self.conn.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.conn.recv(buffer_size)

        return msg_bytes

    def close(self):
        self.conn.close()


if __name__ == '__main__':
    server = Server('localhost', 9999)
    enc_key = KeyManager.read_key('enc_key.txt')
    mac_key = KeyManager.read_key('mac_key.txt')
    des = DES(enc_key)

    while True:
        # upon receiving a message
        cipher = server.recv()
        print('Received Ciphertext: ', cipher.decode('utf-8', errors='ignore'))

        # decrypt message (with MAC) (use des)
        msg_with_mac_bytes = DES.decrypt(des, cipher)
        # split message and MAC (use HMAC class)
        msg_bytes, mac_recv = HMAC.split_HMAC(msg_with_mac_bytes)
        # then calculate the MAC again (use HMAC class)
        mac_calc = HMAC.get_HMAC(msg_bytes, mac_key)

        msg_str = msg_bytes.decode('utf-8')
        print('\nReceived Plaintext: ', msg_str)
        # check mac manually
        print('\nReceived   MAC: ', mac_recv.hex())
        print('Calculated MAC: ', mac_calc.hex())


        # upon sending a message
        msg = input('> ')
        if msg == 'exit':
            break
        msg_bytes = DES.padding(msg).encode("utf-8")

        # calculate mac (use HMAC class)
        mac = hashlib.sha256(str(msg).encode('utf-8'))
        print('Hash: ', mac.hexdigest())
        # encrypt the message together with MAC (use des)
        msg_with_mac_key = msg_bytes + mac_key
        cipher = DES.encrypt(des, msg_with_mac_key)
        print('Ciphertext sent: ', cipher.decode('utf-8', errors='ignore'))
        server.send(cipher)
        
    server.close()
