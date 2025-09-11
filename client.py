# client.py — PSTP клиент

import socket
import json
import time
import hmac
import hashlib
from instructions import read_device_config
from PSTP import Package, Header

SERVER_HOST = '192.168.1.100'  # ЗАМЕНИТЕ НА IP ВАШЕГО СЕРВЕРА
SERVER_PORT = 8080

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

        challenge = s.recv(16)
        print(f"Challenge received: {challenge.hex()}")

        h = hmac.new(shared_secret, challenge, hashlib.sha256)
        response = h.hexdigest()
        print(f"Sending HMAC response: {response}")

        s.sendall(response.encode('utf-8'))

        auth_result = s.recv(8)
        if auth_result == b'AUTH_OK':
            print("Authentication successful!")
        else:
            print(f"Authentication failed: {auth_result}")
            return

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

        print("Sending tunnel request...")
        s.sendall(packed)

        header_bytes = s.recv(28)
        if not header_bytes:
            print("No response from server")
            return

        mac_bytes = s.recv(16)
        header = Header.unpack(header_bytes)
        encrypted_len = header.PackageLen - header.HeaderLen
        encrypted_data = s.recv(encrypted_len)

        full_packet = header_bytes + encrypted_data + mac_bytes

        try:
            _, plaintext = Package.unpack_and_decrypt(full_packet, aes_key, mac_key)
            response = json.loads(plaintext)
            print("Received response from server:")
            print(json.dumps(response, indent=2, ensure_ascii=False))

            if response.get("status") == "ok":
                print("\nSUCCESS! Tunnel ready:")
                print(f"   URL: {response['tunnel_url']}")
                print(f"   Token: {response['token']}")
                print(f"   Expires: {time.ctime(response['expires_at'])}")
            else:
                print("Error:", response.get("message"))

        except Exception as e:
            print(f"Decryption error: {e}")

if __name__ == "__main__":
    main()