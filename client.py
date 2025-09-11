# client.py — PSTP клиент

import socket
import json
import time
import hmac
import hashlib
from instructions import read_device_config
from PSTP import Package, Header

SERVER_HOST = '192.168.1.44'  # ЗАМЕНИТЕ НА IP ВАШЕГО СЕРВЕРА
SERVER_PORT = 8080

def recv_all(sock, n):
    """Получает ровно n байт из сокета"""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def derive_keys(shared_secret: bytes):
    aes_key = Package.derive_key(shared_secret, salt=b'PSTP_AES_SALT')
    mac_key = Package.derive_key(shared_secret, salt=b'PSTP_MAC_SALT')
    return aes_key, mac_key

def main():
    device_id, shared_secret = read_device_config()
    aes_key, mac_key = derive_keys(shared_secret)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"Connecting to {SERVER_HOST}:{SERVER_PORT}...")
        s.connect((SERVER_HOST, SERVER_PORT))

        # Получаем challenge — ТОЧНО 16 байт
        challenge = recv_all(s, 16)
        if not challenge:
            print("❌ Failed to receive challenge")
            return

        print(f"   [Client] Challenge received: {challenge.hex()} ({len(challenge)} bytes)")

        # Вычисляем HMAC от СЫРЫХ БАЙТОВ challenge
        h = hmac.new(shared_secret, challenge, hashlib.sha256)
        response = h.hexdigest()
        print(f"   [Client] Sending HMAC response: {response}")

        s.sendall(response.encode('utf-8'))

        # Ждём ответ аутентификации
        auth_result = recv_all(s, 8)
        if not auth_result:
            print("❌ No auth response from server")
            return

        if auth_result == b'AUTH_OK':
            print("✅ Authentication successful!")
        else:
            print(f"❌ Authentication failed: {auth_result}")
            return

        # Отправляем запрос туннеля
        cmd = {
            "cmd": "request_tunnel",
            "type": "websocket",
            "ttl": 3600
        }
        cmd_json = json.dumps(cmd)

        header = Header(
            DeviceID=device_id,
            Nonce=Package.generate_nonce(),
            Timestamp=int(time.time())
        )
        package = Package(header)
        packed = package.encrypt_and_pack(cmd_json, aes_key, mac_key)

        print("📤 Sending tunnel request...")
        s.sendall(packed)

        # Получаем ответ
        header_bytes = recv_all(s, 28)
        if not header_bytes:
            print("❌ No response header from server")
            return

        mac_bytes = recv_all(s, 16)
        if not mac_bytes:
            print("❌ No MAC from server")
            return

        header = Header.unpack(header_bytes)
        encrypted_len = header.PackageLen - header.HeaderLen
        encrypted_data = recv_all(s, encrypted_len)
        if not encrypted_data:
            print("❌ No encrypted data from server")
            return

        full_packet = header_bytes + encrypted_data + mac_bytes

        try:
            _, plaintext = Package.unpack_and_decrypt(full_packet, aes_key, mac_key)
            response = json.loads(plaintext)
            print("📥 Received response from server:")
            print(json.dumps(response, indent=2, ensure_ascii=False))

            if response.get("status") == "ok":
                print("\n🎉 SUCCESS! Tunnel ready:")
                print(f"   URL: {response['tunnel_url']}")
                print(f"   Token: {response['token']}")
                print(f"   Expires: {time.ctime(response['expires_at'])}")
            else:
                print("❌ Error:", response.get("message"))

        except Exception as e:
            print(f"❌ Decryption error: {e}")

if __name__ == "__main__":
    main()