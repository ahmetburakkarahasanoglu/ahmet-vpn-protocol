import socket
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from security import VPNSession

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 9999

def handshake_paketi_mi(data):
    """[2B len][pubkey][16B salt] formatını hızlıca doğrular."""
    if not data or len(data) < 83: # Minimum 2 + 65 + 16 = 83 byte olmalı
        return False
    try:
        pub_len = struct.unpack(">H", data[:2])[0]
        # Client UncompressedPoint formatı kullanıyor: tam 65 byte olmalı.
        if pub_len != 65 or len(data) != (2 + pub_len + 16):
            return False
        
        peer_pub_key = data[2:2 + pub_len]
        # Uncompressed EC point 0x04 ile başlar.
        if peer_pub_key[0] != 0x04:
            return False
        return True
    except Exception:
        return False

def server_baslat():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))

    print(f"[*] VPN Server {LISTEN_PORT} portunda aktif")

    # key: client_ip -> {"session": VPNSession, "trusted_ports": set[int]}
    sessions = {}

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            if not data: continue
            
            client_ip, client_port = addr

            # =========================
            # HANDSHAKE PHASE
            # =========================
            if handshake_paketi_mi(data):
                try:
                    print(f"[>] Handshake isteği: {client_ip}:{client_port}")

                    pub_len = struct.unpack(">H", data[:2])[0]
                    peer_pub_key = data[2:2 + pub_len]
                    peer_salt = data[2 + pub_len:2 + pub_len + 16]

                    # Veri boş mu kontrolü (Error: data must not be empty engelleyici)
                    if not peer_pub_key or not peer_salt:
                        raise ValueError("Public key veya salt boş!")

                    session = VPNSession()
                    
                    # KRİTİK: İstemcinin gönderdiği peer_salt ile anahtar türetilmeli
                    session.session_kur(peer_pub_key, peer_salt)

                    # Sunucu kendi public key'ini gönderir
                    my_pub_bytes = session.public_key.public_bytes(
                        encoding=serialization.Encoding.X962,
                        format=serialization.PublicFormat.UncompressedPoint
                    )

                    # Response: [2 byte len][pubkey][server_salt]
                    response = struct.pack(">H", len(my_pub_bytes)) + my_pub_bytes + session.salt
                    sock.sendto(response, addr)

                    sessions[client_ip] = {
                        "session": session,
                        "trusted_ports": {client_port},
                    }

                    print(f"[✔] Handshake Başarılı: {client_ip}")
                    continue

                except Exception as e:
                    print(f"[X] Handshake Hatası: {e}")
                    continue

            # =========================
            # DATA PHASE
            # =========================
            client_ctx = sessions.get(client_ip)
            if not client_ctx:
                # El sıkışmayan IP'lerden gelen veriyi yoksay (Güvenlik)
                continue

            session = client_ctx["session"]
            
            try:
                # Paketi çözmeyi dene (HMAC burada doğrulanır)
                ham_veri = session.guvenli_ac(data)

                # Eğer HMAC doğruysa, bu portu güvenli listeye ekle (NAT toleransı)
                if client_port not in client_ctx["trusted_ports"]:
                    client_ctx["trusted_ports"].add(client_port)
                    print(f"[!] Yeni Port Güvenli Listeye Eklendi: {client_port}")

                print(f"[+] Paket Çözüldü: {client_ip} | {len(ham_veri)} byte")
                # Burada TUN interface'e yazma işlemi yapılacak.

            except Exception as e:
                print(f"[!] Yetkisiz Paket Engellendi! Gelen: {client_ip}:{client_port} | {e}")

        except KeyboardInterrupt:
            print("\n[*] Sunucu durduruluyor...")
            break
        except Exception as e:
            print(f"[!] Beklenmedik Döngü Hatası: {e}")

if __name__ == "__main__":
    server_baslat()