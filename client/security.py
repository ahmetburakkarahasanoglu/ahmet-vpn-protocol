import os
import time
import base64
import struct
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization

class VPNSession:
    def __init__(self, psk_key=b"Ahmet-Burak-Ostim-2026"):
        # DH ve Key Separation
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.psk = psk_key
        self.enc_motor = None
        self.auth_key = None
        self.salt = os.urandom(16) # Handshake için lazım
        
        # --- REPLAY PROTECTION & SESSION STATE ---
        self.tx_sequence = 0  # Gönderilen paket numarası
        self.rx_sequence = 0  # Beklenen/En son alınan paket numarası
        self.received_window = set() # Sliding window takibi
        self.window_size = 1000 
        
        self.created_at = None
        self.timeout = 3600
        
    def session_kur(self, peer_public_bytes, peer_salt):
        # Public key'i byte'tan objeye çeviriyoruz (UncompressedPoint formatı için)
        peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public_bytes)
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_pub)
        
        # Key Separation (Enc ve Auth anahtarlarını birbirinden ayırıyoruz)
        enc_raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=peer_salt, info=b'vpn-enc').derive(shared_secret)
        self.enc_motor = Fernet(base64.urlsafe_b64encode(enc_raw))
        
        self.auth_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=peer_salt, info=b'vpn-auth').derive(shared_secret)
        
        self.created_at = time.time()
        print("[*] Anti-Replay destekli session kuruldu.")

    def guvenli_paketle(self, ham_veri):
        """Packet Structure: [Sequence(8b)][Encrypted_Data][HMAC(32b)]"""
        self.tx_sequence += 1
        seq_bytes = struct.pack(">Q", self.tx_sequence) 
        
        # 1. Şifrele
        sifreli = self.enc_motor.encrypt(ham_veri)
        
        # 2. Sequence + Sifreli veriyi imzala (Encrypt-then-MAC)
        paket_govdesi = seq_bytes + sifreli
        h = hmac.HMAC(self.auth_key, hashes.SHA256())
        h.update(paket_govdesi)
        imza = h.finalize()
        
        return paket_govdesi + imza

    def guvenli_ac(self, paket):
        imza_boyutu = 32
        seq_boyutu = 8
        
        if len(paket) < (imza_boyutu + seq_boyutu):
            raise Exception("Paket boyutu çok küçük!")

        imza = paket[-imza_boyutu:]
        govde = paket[:-imza_boyutu]
        
        # 1. Bütünlük Kontrolü (HMAC)
        h = hmac.HMAC(self.auth_key, hashes.SHA256())
        h.update(govde)
        try:
            h.verify(imza)
        except:
            raise Exception("HMAC Dogrulanamadi! Paket kurcalanmış.")
            
        # 2. Anti-Replay Kontrolü
        seq = struct.unpack(">Q", govde[:seq_boyutu])[0]
        sifreli_veri = govde[seq_boyutu:]
        
        if seq <= self.rx_sequence:
            if seq in self.received_window or seq < (self.rx_sequence - self.window_size):
                raise Exception(f"REPLAY ATTACK TESPIT EDILDI! Seq: {seq}")
        
        # Pencereyi güncelle
        self.received_window.add(seq)
        if len(self.received_window) > self.window_size:
            self.received_window.remove(min(self.received_window))
        
        self.rx_sequence = max(self.rx_sequence, seq)
        
        # 3. Şifreyi Çöz
        return self.enc_motor.decrypt(sifreli_veri)