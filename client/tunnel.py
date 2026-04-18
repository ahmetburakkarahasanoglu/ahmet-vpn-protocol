import os
import struct
import socket
import threading
from fcntl import ioctl
from cryptography.hazmat.primitives import serialization
from security import VPNSession

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999
CLIENT_PORT = 55555
SABIT_TUZ = b"Ahmet-Burak-2026"

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def tun_create(name="tun0"):
    tun = open("/dev/net/tun", "r+b", buffering=0)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    ioctl(tun, TUNSETIFF, ifr)
    return tun


def listener(sock, tun, session):
    while True:
        data, _ = sock.recvfrom(4096)
        try:
            dec = session.guvenli_ac(data)
            os.write(tun.fileno(), dec)
        except:
            pass


session = VPNSession()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind(("0.0.0.0", CLIENT_PORT))

tun = tun_create("tun0")


# HANDSHAKE
pub = session.public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

pkt = struct.pack(">H", len(pub)) + pub + SABIT_TUZ
sock.sendto(pkt, (SERVER_IP, SERVER_PORT))

data, _ = sock.recvfrom(4096)

pub_len = struct.unpack(">H", data[:2])[0]
peer = data[2:2+pub_len]

session.session_kur(peer, SABIT_TUZ)

print("[+] handshake OK")


threading.Thread(target=listener, args=(sock, tun, session), daemon=True).start()


while True:
    packet = os.read(tun.fileno(), 2048)
    if not packet:
        continue

    enc = session.guvenli_paketle(packet)
    sock.sendto(enc, (SERVER_IP, SERVER_PORT))