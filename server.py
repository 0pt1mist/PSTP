# server.py — PSTP сервер

import socket
import threading
import json
import time
import secrets
from server_auth import DeviceAuthenticator
from instructions import read_server_allowed_devices
from PSTP import Package, Header
from connection import recv_all

HOST = '0.0.0.0'
PORT = 8080

class PSTPServer:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        allowed_devices = read_server_allowed_devices()
        self.auth = DeviceAuthenticator(allowed_devices)
        self.active_sessions = {}

    def derive_keys(self, shared_secret: bytes):
        aes_key = Package.derive_key(shared_secret, salt=b'PSTP_AES_SALT')
        mac_key = Package.derive_key(shared_secret, salt=b'PSTP_MAC_SALT')
        return aes_key, mac_key

    def handle_client(self, conn, addr):
        print(f"[+] New connection from {addr}")
        try:
            device_id = "phone01"
            challenge = self.auth.generate_challenge(device_id)
            if not challenge:
                conn.sendall(b'FORBIDDEN')
                conn.close()
                return

            conn.sendall(challenge)
            print(f"   -> Challenge sent: {challenge.hex()}")

            response = conn.recv(64).decode('utf-8').strip()
            print(f"   -> Response received: {response}")

            authenticated_device = self.auth.verify_response(challenge.hex(), response)
            if not authenticated_device:
                conn.sendall(b'AUTH_FAIL')
                conn.close()
                print("   -> Authentication failed")
                return

            print(f"   -> Authentication successful for {authenticated_device}")

            shared_secret = read_server_allowed_devices()[authenticated_device]
            aes_key, mac_key = self.derive_keys(shared_secret)
            self.active_sessions[authenticated_device] = (aes_key, mac_key)

            conn.sendall(b'AUTH_OK')
            self.message_loop(conn, authenticated_device, aes_key, mac_key)

        except Exception as e:
            print(f"   -> Error: {e}")
        finally:
            conn.close()
            print(f"[-] Connection from {addr} closed")

    def message_loop(self, conn, device_id, aes_key, mac_key):
        while True:
            try:
                header_bytes = recv_all(conn, 28)
                if not header_bytes:
                    break

                mac_bytes = recv_all(conn, 16)
                if not mac_bytes:
                    break

                header = Header.unpack(header_bytes)
                encrypted_len = header.PackageLen - header.HeaderLen
                encrypted_data = recv_all(conn, encrypted_len)
                if not encrypted_data:
                    break

                full_packet = header_bytes + encrypted_data + mac_bytes

                try:
                    package, plaintext = Package.unpack_and_decrypt(full_packet, aes_key, mac_key)
                    print(f"   <- Received: {plaintext}")

                    try:
                        cmd = json.loads(plaintext)
                        if cmd.get("cmd") == "request_tunnel":
                            response = {
                                "status": "ok",
                                "tunnel_url": "wss://home.local:8081/tunnel/" + secrets.token_urlsafe(8),
                                "token": secrets.token_urlsafe(16),
                                "expires_at": int(time.time()) + 3600
                            }
                        else:
                            response = {"status": "error", "message": "Unknown command"}
                    except json.JSONDecodeError:
                        response = {"status": "error", "message": "Invalid JSON"}

                    response_text = json.dumps(response)
                    resp_header = Header(
                        DeviceID="server",
                        Nonce=Package.generate_nonce(),
                        Timestamp=int(time.time())
                    )
                    resp_package = Package(resp_header)
                    packed_response = resp_package.encrypt_and_pack(response_text, aes_key, mac_key)
                    conn.sendall(packed_response)
                    print(f"   -> Sent: {response}")

                except ValueError as e:
                    print(f"   -> Decryption error: {e}")
                    conn.sendall(b'DECRYPT_FAIL')

            except Exception as e:
                print(f"   -> Message loop error: {e}")
                break

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)
            print(f"PSTP server started on {self.host}:{self.port}")
            print("Waiting for connections...")

            while True:
                conn, addr = s.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                client_thread.start()

if __name__ == "__main__":
    server = PSTPServer()
    server.start()