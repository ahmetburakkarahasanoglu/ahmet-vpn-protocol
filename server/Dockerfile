FROM python:3.12-slim

# Gerekli ağ araçları
RUN apt update && apt install -y net-tools iproute2

WORKDIR /app

# Şifreleme kütüphanesi
RUN pip install cryptography

# Dosyaları kopyala
COPY src/core/server.py .
COPY src/core/security.py .

# UDP portunu aç
EXPOSE 9999/udp

# -u parametresi logların anında (unbuffered) ekrana düşmesini sağlar
CMD ["python", "-u", "server.py"]