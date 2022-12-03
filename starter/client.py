
import socket
from crypto import KeyManager, DES, HMAC
import hashlib


class Client:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.addr, self.port))

    def send(self, msg_bytes: bytes):
        self.s.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.s.recv(self.buffer_size)

        return msg_bytes

    def close(self):
        self.s.close()


if __name__ == '__main__':
    client = Client('localhost', 9999)
    enc_key = KeyManager().read_key('enc_key.txt')
    mac_key = KeyManager().read_key('mac_key.txt')
    des = DES(enc_key)

    while True:
        # upon sending a message
        msg = input('> ')
        if msg == 'exit':
            break
        msg_bytes = DES.padding(msg).encode("utf-8")
        
        # calculate mac
        mac = HMAC.get_HMAC(msg_bytes, mac_key)
        print('Hash: ', mac.hex())
        # encrypt message together with MAC (use des)
        msg_with_mac = msg_bytes + mac
        cipher = DES.encrypt(des, msg_with_mac)
        print('Ciphertext Sent: ', cipher.decode('utf-8', errors='ignore'))
        client.send(cipher)


        # upon receiving a message
        cipher = client.recv()
        print('Received Ciphertext: ', cipher.decode('utf-8', errors='ignore'))
        # decrypt message (with MAC) (use des)
        msg_with_mac_bytes = DES.decrypt(des, cipher)
        # split the message and the MAC (use HMAC class)
        msg, mac_recv = HMAC.split_HMAC(msg_with_mac_bytes)
        # then calculate the MAC again (use HMAC class)
        mac_calc = HMAC.get_HMAC(msg, mac_key)

        msg_str = msg.decode('utf-8')
        print('\nReceived Plaintext: ', msg_str)
        print('\nSender MAC: ', mac_recv.hex())
        print('Rcever MAC: ', mac_calc.hex())



    client.close()
