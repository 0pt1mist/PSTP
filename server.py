import socket
import threading
import json
import time
import secrets
import asyncio
from server_auth import DeviceAuthenticator
from instructions import read_server_allowed_devices
from PSTP import Package, Header
from connection import recv_all
from websocket_tunnel import tunnel_server

HOST = '0.0.0.0'
PORT = 8080

class PSTPServer:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        allowed_devices = read_server_allowed_devices()
        self.auth = DeviceAuthenticator(allowed_devices)
        self.active_sessions = {}
        self._cleanup_thread = None
        self._stop_cleanup = False
        self._websocket_thread = None
        self.websocket_loop = None

    async def initialize_websocket_tunnel(self):
        """Инициализирует и запускает WebSocket туннель"""
        try:
            print("🔄 Initializing WebSocket tunnel...")
            self.websocket_loop = asyncio.get_running_loop()
            await tunnel_server.start()
        except Exception as e:
            print(f"❌ WebSocket tunnel initialization failed: {e}")

    def start_websocket_tunnel(self):
        """Запускает WebSocket туннель в отдельном потоке"""
        def run_websocket_tunnel():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.websocket_loop = loop
            loop.run_until_complete(self.initialize_websocket_tunnel())
        
        self._websocket_thread = threading.Thread(target=run_websocket_tunnel, daemon=True)
        self._websocket_thread.start()
        print("✅ WebSocket tunnel thread started")

    def start_cleanup_thread(self):
        """Запускает фоновый поток для очистки устаревших сессий и challenges"""
        def cleanup_loop():
            while not self._stop_cleanup:
                time.sleep(60)
                self.cleanup_expired_sessions()
                if hasattr(self.auth, 'cleanup_expired_challenges'):
                    self.auth.cleanup_expired_challenges()
        
        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def cleanup_expired_sessions(self):
        """Очищает устаревшие сессии"""
        current_time = time.time()
        expired_devices = []
        
        for device_id, session_data in self.active_sessions.items():
            last_activity = session_data.get('last_activity', 0)
            if current_time - last_activity > 3600:
                expired_devices.append(device_id)
        
        for device_id in expired_devices:
            del self.active_sessions[device_id]
            print(f"   [Cleanup] Removed expired session for {device_id}")

    def derive_keys(self, shared_secret: bytes):
        aes_key = Package.derive_key(shared_secret, salt=b'PSTP_AES_SALT')
        mac_key = Package.derive_key(shared_secret, salt=b'PSTP_MAC_SALT')
        return aes_key, mac_key

    def update_session_activity(self, device_id):
        """Обновляет время последней активности для сессии"""
        if device_id in self.active_sessions:
            self.active_sessions[device_id]['last_activity'] = time.time()

    def handle_client(self, conn, addr):
        print(f"[+] New connection from {addr}")
        device_id = None

        try:
            # Получаем DeviceID из первого сообщения
            initial_header_bytes = recv_all(conn, Header.HEADER_SIZE)
            if not initial_header_bytes:
                print("   ❌ No initial header from client")
                conn.close()
                return

            initial_header = Header.unpack(initial_header_bytes)
            device_id = initial_header.DeviceID  # Теперь это строка
            print(f"   → Client identified as: '{device_id}' (type: {type(device_id).__name__})")

            # ИСПРАВЛЕНИЕ: нормализуем device_id
            if isinstance(device_id, bytes):
                device_id = device_id.decode('utf-8', errors='ignore').strip()
            elif isinstance(device_id, str):
                device_id = device_id.strip()
            else:
                device_id = str(device_id).strip()

            print(f"   → Normalized device ID: '{device_id}'")

            # Аутентификация...
            challenge = self.auth.generate_challenge(device_id)
            if not challenge:
                print(f"   ❌ Device '{device_id}' not allowed")
                conn.sendall(b'FORBIDDEN')
                conn.close()
                return

            conn.sendall(challenge)
            print(f"   → Challenge sent: {challenge.hex()} ({len(challenge)} bytes)")

            response_bytes = recv_all(conn, 64)
            if not response_bytes:
                print("   ❌ No response from client")
                conn.close()
                return

            response = response_bytes.decode('utf-8').strip()
            print(f"   → Response received: {response}")

            authenticated_device = self.auth.verify_response(challenge, response)
            if not authenticated_device:
                conn.sendall(b'AUTH_FAIL')
                conn.close()
                print("   → Authentication failed")
                return

            print(f"   → Authentication successful for '{authenticated_device}'")

            shared_secret = self.auth.allowed_devices[authenticated_device]
            aes_key, mac_key = self.derive_keys(shared_secret)

            self.active_sessions[authenticated_device] = {
                'aes_key': aes_key,
                'mac_key': mac_key,
                'last_activity': time.time(),
                'connection_time': time.time(),
                'socket_conn': conn
            }

            # ИСПРАВЛЕНИЕ: НЕМЕДЛЕННО отправляем ответ об аутентификации
            response = json.dumps({"status": "authenticated"})
            resp_header = Header(
                DeviceID="server",
                Nonce=Package.generate_nonce(),
                Timestamp=int(time.time())
            )
            resp_package = Package(resp_header)
            packed_response = resp_package.encrypt_and_pack(response, aes_key, mac_key)
            conn.sendall(packed_response)
            print("   → Authentication response sent to client")

            # Только после успешной отправки ответа переходим к message_loop
            print(f"   → Starting message loop for '{authenticated_device}'")
            self.message_loop(conn, authenticated_device, aes_key, mac_key)

        except Exception as e:
            print(f"   → Error in handle_client: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if device_id and device_id in self.active_sessions:
                self.active_sessions[device_id].pop('socket_conn', None)
            conn.close()
            print(f"[-] Connection from {addr} closed")
    
    def message_loop(self, conn, device_id, aes_key, mac_key):
        """Основной цикл обработки сообщений от клиента"""
        while True:
            try:
                self.update_session_activity(device_id)
                
                header_bytes = recv_all(conn, Header.HEADER_SIZE)
                if not header_bytes:
                    print(f"   → Client '{device_id}' disconnected gracefully")
                    break

                temp_header = Header.unpack(header_bytes)
                
                if not Package.is_packet_fresh(temp_header.Timestamp):
                    print(f"   → Stale packet from '{device_id}', ignoring")
                    error_response = json.dumps({"status": "error", "message": "Stale packet"})
                    self.send_encrypted_response(conn, error_response, aes_key, mac_key)
                    continue

                encrypted_len = temp_header.PackageLen - temp_header.HeaderLen
                encrypted_data = recv_all(conn, encrypted_len)
                if not encrypted_data:
                    print(f"   → No encrypted data from '{device_id}'")
                    break

                mac_bytes = recv_all(conn, 16)
                if not mac_bytes:
                    print(f"   → No MAC from '{device_id}'")
                    break

                full_packet = header_bytes + encrypted_data + mac_bytes

                try:
                    package, plaintext = Package.unpack_and_decrypt(full_packet, aes_key, mac_key)
                    print(f"   ← Received from '{device_id}': {plaintext}")

                    # Обрабатываем команду
                    response = self.process_command(plaintext, device_id, conn, aes_key, mac_key)
                    
                    # Отправляем ответ
                    self.send_encrypted_response(conn, response, aes_key, mac_key)
                    print(f"   → Sent to '{device_id}': {response}")

                except ValueError as e:
                    print(f"   → Decryption/MAC error from '{device_id}': {e}")
                    error_response = json.dumps({"status": "error", "message": "Decryption failed"})
                    self.send_encrypted_response(conn, error_response, aes_key, mac_key)
                    
                except Exception as e:
                    print(f"   → Processing error from '{device_id}': {e}")
                    error_response = json.dumps({"status": "error", "message": "Processing error"})
                    self.send_encrypted_response(conn, error_response, aes_key, mac_key)

            except socket.timeout:
                print(f"   → Socket timeout for '{device_id}', continuing...")
                continue
                
            except Exception as e:
                print(f"   → Message loop error for '{device_id}': {e}")
                break

    def process_command(self, plaintext, device_id, conn, aes_key, mac_key):
        """Обрабатывает команды от клиента"""
        try:
            cmd = json.loads(plaintext)
            command_type = cmd.get("cmd")
            
            if command_type == "request_tunnel":
                # Генерируем туннель через WebSocket сервер
                tunnel_info = tunnel_server.generate_tunnel(device_id)
                return {
                    "status": "ok",
                    "tunnel_url": tunnel_info['tunnel_url'],
                    "token": tunnel_info['token'],
                    "expires_at": tunnel_info['expires_at'],
                    "device_id": device_id
                }
                
            elif command_type == "ping":
                return {
                    "status": "ok", 
                    "message": "pong",
                    "timestamp": int(time.time()),
                    "device_id": device_id
                }
                    
            elif command_type == "send_to_tunnel":
                # Сообщение для отправки через туннель
                message_data = cmd.get("data", {})
                print(f"   📤 [SERVER → TUNNEL] Device: '{device_id}'")
                print(f"      Data: {json.dumps(message_data, indent=6)}")
                
                # ИСПРАВЛЕНИЕ: Безопасная отправка через WebSocket
                if self.websocket_loop and self.websocket_loop.is_running():
                    future = asyncio.run_coroutine_threadsafe(
                        tunnel_server.send_to_device(device_id, message_data),
                        self.websocket_loop
                    )
                    # Не ждем завершения, чтобы не блокировать
                    print(f"   → WebSocket message scheduled for delivery")
                
                return {
                    "status": "ok",
                    "message": "delivered_to_tunnel",
                    "timestamp": int(time.time())
                }
                
            elif command_type == "status":
                # Проверяем WebSocket соединение
                websocket_active = hasattr(tunnel_server, 'connections') and device_id in tunnel_server.connections
                return {
                    "status": "ok",
                    "device_status": "active",
                    "websocket_connected": websocket_active,
                    "session_age": int(time.time() - self.active_sessions[device_id]['connection_time']),
                    "server_time": int(time.time())
                }
            else:
                return {"status": "error", "message": "Unknown command"}
                
        except json.JSONDecodeError:
            return {"status": "error", "message": "Invalid JSON"}

    def send_encrypted_response(self, conn, response_text, aes_key, mac_key):
        """Отправляет зашифрованный ответ клиенту"""
        if isinstance(response_text, dict):
            response_text = json.dumps(response_text)
            
        resp_header = Header(
            DeviceID="server",
            Nonce=Package.generate_nonce(),
            Timestamp=int(time.time())
        )
        resp_package = Package(resp_header)
        packed_response = resp_package.encrypt_and_pack(response_text, aes_key, mac_key)
        conn.sendall(packed_response)

    def start(self):
        """Запускает PSTP сервер"""
        print("🚀 Starting PSTP Server with WebSocket tunnel support...")
        
        self.start_cleanup_thread()
        self.start_websocket_tunnel()
        
        # Даем время на инициализацию WebSocket
        time.sleep(2)
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(1.0)
            
            try:
                s.bind((self.host, self.port))
                s.listen(5)
                print(f"✅ PSTP server started on {self.host}:{self.port}")
                print(f"📊 Allowed devices: {list(self.auth.allowed_devices.keys())}")
                print("🎯 WebSocket tunnel will auto-cleanup on startup")
                print("Waiting for connections...")

                while True:
                    try:
                        conn, addr = s.accept()
                        conn.settimeout(10.0)
                        client_thread = threading.Thread(
                            target=self.handle_client, 
                            args=(conn, addr), 
                            daemon=True
                        )
                        client_thread.start()
                        print(f"📈 Active PSTP threads: {threading.active_count()}")
                        
                    except socket.timeout:
                        continue
                        
            except KeyboardInterrupt:
                print("\n🛑 Server shutdown requested...")
            except Exception as e:
                print(f"❌ Server error: {e}")
            finally:
                self._stop_cleanup = True
                print("👋 PSTP server stopped")

if __name__ == "__main__":
    # Установите: pip install websockets
    try:
        import websockets
        print("🔧 Starting server with WebSocket tunnel cleanup...")
        server = PSTPServer()
        server.start()
    except ImportError:
        print("❌ Please install websockets: pip install websockets")
        # Запускаем только PSTP сервер если WebSocket не доступен
        server = PSTPServer()
        server.start()