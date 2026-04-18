# 🔐 Custom VPN Protocol (Python)

Bu proje, sıfırdan tasarlanmış bir **VPN protokolü ve tünelleme sistemi** prototipidir. Amaç; modern VPN'lerde kullanılan kriptografik ve ağ katmanı prensiplerini öğrenmek ve uygulamaktır.

---

## 🚀 Özellikler

* 🔑 **ECDH (Elliptic Curve Diffie-Hellman)** ile anahtar değişimi
* 🔐 **HKDF ile anahtar türetme (Key Derivation)**
* 🔀 **Key Separation (ENC / AUTH ayrımı)**
* 🛡 **Encrypt-then-MAC (EtM) modeli**
* 🔢 **Sequence Number ile Replay Protection**
* 🧠 **Sliding Window mantığı (anti-replay)**
* ⏱ **Constant-time comparison (timing attack koruması)**
* 🔁 **Perfect Forward Secrecy (PFS)**
* 🌐 **UDP tabanlı tünelleme**
* 🧩 **Linux TUN interface entegrasyonu**

---

## 🏗 Mimari

### 1. Handshake (El Sıkışma)

* Client → Server:

  ```
  [pubkey_length][public_key][salt]
  ```
* Server → Client:

  ```
  [pubkey_length][public_key][salt]
  ```

Bu aşamada:

* Ortak secret oluşturulur (ECDH)
* HKDF ile anahtarlar türetilir

---

### 2. Veri Transferi (Data Phase)

Paket yapısı:

```
[sequence_number][encrypted_data][HMAC]
```

Adımlar:

1. Veri şifrelenir (Encryption)
2. Şifreli veri HMAC ile imzalanır
3. Sequence number eklenir

---

### 3. Güvenlik Katmanları

| Mekanizma       | Amaç                    |
| --------------- | ----------------------- |
| ECDH            | Gizli anahtar paylaşımı |
| HKDF            | Güvenli anahtar türetme |
| HMAC            | Veri bütünlüğü          |
| Sequence Number | Replay attack engelleme |
| PFS             | Geçmiş trafiği koruma   |
| Constant-time   | Timing attack önleme    |

---

## 📂 Proje Yapısı

```
.
├── client.py        # VPN Client (TUN + UDP)
├── server.py        # VPN Server (UDP)
├── security.py      # Kriptografik işlemler (VPNSession)
└── README.md
```

---

## ⚙️ Kurulum

### Gereksinimler

* Python 3.10+
* Linux (TUN desteği için)
* root / sudo yetkisi

### Paket kurulumu

```bash
pip install cryptography
```

---

## ▶️ Çalıştırma

### 1. Server başlat

```bash
python3 server.py
```

### 2. Client başlat

```bash
sudo python3 client.py
```

---

## 🌐 Network Ayarı

TUN interface’e IP atamak için:

```bash
sudo ip addr add 10.8.0.1/24 dev tun0
sudo ip link set tun0 up
```

---

## 🧪 Test Senaryosu

* Client → TUN interface üzerinden paket gönderir
* Paket şifrelenir
* UDP ile server’a gider
* Server doğrular ve çözer

---

## ⚠️ Bilinen Kısıtlar

Bu proje bir **öğrenci projesi / prototiptir**, production kullanımı için uygun değildir.

Eksikler:

* ❌ Kimlik doğrulama (authentication)
* ❌ Sertifika sistemi
* ❌ NAT traversal
* ❌ Multi-client gelişmiş yönetim
* ❌ Packet fragmentation (tam çözüm yok)
* ❌ Session timeout / rekey mekanizması

---

## 🎯 Amaç

Bu proje şunları öğrenmek için geliştirilmiştir:

* VPN protokol tasarımı
* Kriptografi uygulamaları
* Network programming (UDP / TUN)
* Güvenlik mekanizmaları (MITM, Replay vs.)

---

## 📌 Not

Bu proje:

> “Production VPN” değil
> “Custom VPN Protocol Prototype” olarak değerlendirilmelidir.



