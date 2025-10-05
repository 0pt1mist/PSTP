import socket
import json
import time
import hmac
import hashlib
import threading
import asyncio
import websockets
from instructions import read_device_config
from PSTP import Package, Header

SERVER_HOST = 'localhost'
SERVER_PORT = 8080
WEBSOCKET_HOST = 'localhost'
WEBSOCKET_PORT = 8081

class PSTPClient:
    def __init__(self):
        self.device_id, self.shared_secret = read_device_config()
        self.aes_key, self.mac_key = self.derive_keys(self.shared_secret)
        self.connected = False
        self.socket = None
        self.tunnel_info = None

    def recv_all(self, sock, n):
        """Получает ровно n байт из сокета"""
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)

    def derive_keys(self, shared_secret: bytes):
        aes_key = Package.derive_key(shared_secret, salt=b'PSTP_AES_SALT')
        mac_key = Package.derive_key(shared_secret, salt=b'PSTP_MAC_SALT')
        return aes_key, mac_key

    def send_encrypted_command(self, command: dict):
        """Отправляет зашифрованную команду на сервер"""
        if not self.connected or not self.socket:
            raise ConnectionError("Not connected to server")

        cmd_json = json.dumps(command)
        header = Header(
            DeviceID=self.device_id,
            Nonce=Package.generate_nonce(),
            Timestamp=int(time.time())
        )
        package = Package(header)
        packed = package.encrypt_and_pack(cmd_json, self.aes_key, self.mac_key)
        
        print(f"   [Client] Sending encrypted command: {command.get('cmd', 'unknown')}")
        self.socket.sendall(packed)
        return self.receive_response()

    def receive_response(self):
        """Получает и расшифровывает ответ от сервера"""
        if not self.connected or not self.socket:
            raise ConnectionError("Not connected to server")

        print("   [Client] Waiting for server response...")
        
        # Читаем заголовок
        header_bytes = self.recv_all(self.socket, Header.HEADER_SIZE)
        if not header_bytes:
            raise ConnectionError("No response header from server")

        header = Header.unpack(header_bytes)
        encrypted_len = header.PackageLen - header.HeaderLen
        
        # Читаем зашифрованные данные
        encrypted_data = self.recv_all(self.socket, encrypted_len)
        if not encrypted_data:
            raise ConnectionError("No encrypted data from server")

        # Читаем MAC
        mac_bytes = self.recv_all(self.socket, 16)
        if not mac_bytes:
            raise ConnectionError("No MAC from server")

        # Собираем полный пакет и расшифровываем
        full_packet = header_bytes + encrypted_data + mac_bytes
        
        try:
            _, plaintext = Package.unpack_and_decrypt(full_packet, self.aes_key, self.mac_key)
            response = json.loads(plaintext)
            print(f"   [Client] Received response: {response.get('status', 'unknown')}")
            return response
        except Exception as e:
            raise ValueError(f"Decryption error: {e}")

    def authenticate(self):
        """Проходит аутентификацию на сервере"""
        print(f"Connecting to {SERVER_HOST}:{SERVER_PORT}...")
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10.0)  # Таймаут на все операции
            self.socket.connect((SERVER_HOST, SERVER_PORT))
            
            # Сначала отправляем идентификацию
            ident_header = Header(
                DeviceID=self.device_id,
                Nonce=Package.generate_nonce(),
                Timestamp=int(time.time())
            )
            self.socket.sendall(ident_header.pack())
            print(f"   [Client] Sent identification header for device: '{self.device_id}'")

            # Получаем challenge
            challenge = self.recv_all(self.socket, 16)
            if not challenge:
                print("❌ Failed to receive challenge")
                return False

            print(f"   [Client] Challenge received: {challenge.hex()} ({len(challenge)} bytes)")

            # Вычисляем HMAC
            h = hmac.new(self.shared_secret, challenge, hashlib.sha256)
            response = h.hexdigest()
            print(f"   [Client] Sending HMAC response: {response}")

            self.socket.sendall(response.encode('utf-8'))
            print("   [Client] HMAC response sent, waiting for authentication result...")

            # ИСПРАВЛЕНИЕ: Получаем ответ аутентификации ОДНИМ блоком
            header_bytes = self.recv_all(self.socket, Header.HEADER_SIZE)
            if not header_bytes:
                print("❌ No auth response header from server")
                return False

            temp_header = Header.unpack(header_bytes)
            encrypted_len = temp_header.PackageLen - temp_header.HeaderLen
            
            encrypted_data = self.recv_all(self.socket, encrypted_len)
            if not encrypted_data:
                print("❌ No auth encrypted data from server")
                return False

            mac_bytes = self.recv_all(self.socket, 16)
            if not mac_bytes:
                print("❌ No auth MAC from server")
                return False

            full_packet = header_bytes + encrypted_data + mac_bytes

            try:
                _, plaintext = Package.unpack_and_decrypt(full_packet, self.aes_key, self.mac_key)
                auth_response = json.loads(plaintext)
                if auth_response.get("status") == "authenticated":
                    print("✅ Authentication successful!")
                    self.connected = True
                    return True
                else:
                    print(f"❌ Authentication failed: {auth_response}")
                    return False
            except Exception as e:
                print(f"❌ Auth response decryption error: {e}")
                return False

        except socket.timeout:
            print("❌ Authentication timeout - server not responding")
            return False
        except ConnectionRefusedError:
            print("❌ Connection refused - server may be down")
            return False
        except Exception as e:
            print(f"❌ Authentication error: {e}")
            return False

    def request_tunnel(self):
        """Запрашивает туннель у сервера"""
        if not self.connected:
            print("❌ Not authenticated")
            return None

        cmd = {
            "cmd": "request_tunnel",
            "type": "websocket",
            "ttl": 3600,
            "device_id": self.device_id
        }

        print("📤 Sending tunnel request...")
        try:
            response = self.send_encrypted_command(cmd)
            
            if response.get("status") == "ok":
                self.tunnel_info = response
                print("🎉 Tunnel created successfully!")
                print(f"   URL: {response['tunnel_url']}")
                print(f"   Token: {response['token']}")
                print(f"   Expires: {time.ctime(response['expires_at'])}")
                return response
            else:
                print(f"❌ Tunnel request failed: {response}")
                return None
        except Exception as e:
            print(f"❌ Error sending tunnel request: {e}")
            return None

    def send_ping(self):
        """Отправляет ping команду"""
        if not self.connected:
            print("❌ Not authenticated")
            return None

        cmd = {
            "cmd": "ping",
            "message": "Hello from client!",
            "timestamp": int(time.time()),
            "device_id": self.device_id
        }

        print("📤 Sending ping...")
        try:
            response = self.send_encrypted_command(cmd)
            
            if response.get("status") == "ok":
                print(f"✅ Ping response: {response.get('message', 'pong')}")
                return response
            else:
                print(f"❌ Ping failed: {response}")
                return None
        except Exception as e:
            print(f"❌ Error sending ping: {e}")
            return None

    def send_tunnel_message(self, message_data: dict):
        """Отправляет сообщение через туннель"""
        if not self.connected:
            print("❌ Not authenticated")
            return None

        cmd = {
            "cmd": "send_to_tunnel",
            "data": message_data,
            "timestamp": int(time.time()),
            "device_id": self.device_id
        }

        print("📤 Sending message to tunnel...")
        try:
            response = self.send_encrypted_command(cmd)
            
            if response.get("status") == "ok":
                print(f"✅ Message delivered to tunnel: {response.get('message', 'delivered')}")
                return response
            else:
                print(f"❌ Message delivery failed: {response}")
                return None
        except Exception as e:
            print(f"❌ Error sending tunnel message: {e}")
            return None

    def get_status(self):
        """Запрашивает статус у сервера"""
        if not self.connected:
            print("❌ Not authenticated")
            return None

        cmd = {
            "cmd": "status",
            "timestamp": int(time.time()),
            "device_id": self.device_id
        }

        print("📤 Requesting status...")
        try:
            response = self.send_encrypted_command(cmd)
            
            if response.get("status") == "ok":
                status_info = {
                    "device_status": response.get("device_status", "unknown"),
                    "websocket_connected": response.get("websocket_connected", False),
                    "session_age": response.get("session_age", 0),
                    "server_time": time.ctime(response.get("server_time", time.time()))
                }
                print(f"✅ Status: {json.dumps(status_info, indent=2)}")
                return response
            else:
                print(f"❌ Status request failed: {response}")
                return None
        except Exception as e:
            print(f"❌ Error getting status: {e}")
            return None

    async def connect_to_tunnel(self):
        """Подключается к WebSocket туннелю"""
        if not self.tunnel_info:
            print("❌ No tunnel info available. Request tunnel first.")
            return None

        token = self.tunnel_info['token']
        # ИСПРАВЛЕНИЕ: Используем правильный URL для локального тестирования
        tunnel_url = f"ws://localhost:8081/tunnel/{secrets.token_urlsafe(8)}?token={token}"
        
        print(f"🔗 Connecting to WebSocket tunnel: {tunnel_url}")
        
        try:
            # ИСПРАВЛЕНИЕ: Убираем extra_headers и используем простой connect
            async with websockets.connect(tunnel_url) as websocket:
                print("✅ Connected to WebSocket tunnel!")
                print("Type messages to send through tunnel (or 'quit' to exit):")
                
                # Задача для получения сообщений
                async def receive_messages():
                    try:
                        async for message in websocket:
                            try:
                                data = json.loads(message)
                                print(f"\n📨 [TUNNEL] Received: {json.dumps(data, indent=2)}")
                                print("> ", end="", flush=True)
                            except json.JSONDecodeError:
                                print(f"\n📨 [TUNNEL] Raw message: {message}")
                                print("> ", end="", flush=True)
                    except websockets.exceptions.ConnectionClosed:
                        print("\n🔌 Tunnel connection closed")
                    except Exception as e:
                        print(f"\n❌ Error in receive_messages: {e}")
                
                # Запускаем получение сообщений в фоне
                receive_task = asyncio.create_task(receive_messages())
                
                # Основной цикл отправки сообщений
                try:
                    while True:
                        try:
                            # Асинхронный ввод
                            message_text = await asyncio.get_event_loop().run_in_executor(
                                None, input, "> "
                            )
                            
                            if message_text.lower() in ['quit', 'exit', 'q']:
                                break
                            
                            if message_text.strip():
                                message = {
                                    "device_id": self.device_id,
                                    "message": message_text,
                                    "timestamp": time.time(),
                                    "type": "user_message",
                                    "direction": "client_to_server"
                                }
                                
                                await websocket.send(json.dumps(message))
                                print(f"📤 [TUNNEL] Sent: {message_text}")
                                
                        except (EOFError, KeyboardInterrupt):
                            break
                        except Exception as e:
                            print(f"❌ Input error: {e}")
                            break
                
                finally:
                    receive_task.cancel()
                    try:
                        await receive_task
                    except asyncio.CancelledError:
                        pass
                    except Exception as e:
                        print(f"❌ Error cancelling receive task: {e}")
                        
        except websockets.exceptions.InvalidStatusCode as e:
            print(f"❌ Connection refused: {e.status_code}")
            if e.status_code == 401:
                print("   💡 Check if the token is valid and not expired")
            elif e.status_code == 403:
                print("   💡 Device not authorized for tunnel access")
        except websockets.exceptions.ConnectionClosedError as e:
            print(f"❌ Connection closed unexpectedly: {e}")
        except Exception as e:
            print(f"❌ Failed to connect to tunnel: {e}")
            import traceback
            traceback.print_exc()
            return None

        print("👋 Disconnected from WebSocket tunnel")
        return True

    def interactive_mode(self):
        """Интерактивный режим работы клиента"""
        if not self.authenticate():
            return

        print("\n" + "="*50)
        print("🚀 PSTP Client - Interactive Mode")
        print("="*50)
        
        while self.connected:
            print("\nAvailable commands:")
            print("1. request_tunnel - Request WebSocket tunnel")
            print("2. ping - Send ping to server")
            print("3. status - Get server status")
            print("4. send_message - Send test message through tunnel")
            print("5. connect_tunnel - Connect to WebSocket tunnel")
            print("6. disconnect - Disconnect from server")
            print("7. exit - Exit program")
            
            try:
                choice = input("\nEnter command number or name: ").strip().lower()
                
                if choice in ['1', 'request_tunnel']:
                    self.request_tunnel()
                    
                elif choice in ['2', 'ping']:
                    self.send_ping()
                    
                elif choice in ['3', 'status']:
                    self.get_status()
                    
                elif choice in ['4', 'send_message']:
                    message = {
                        "text": f"Hello from PSTP client {self.device_id}!",
                        "type": "test_message",
                        "counter": int(time.time()),
                        "device_id": self.device_id
                    }
                    self.send_tunnel_message(message)
                    
                elif choice in ['5', 'connect_tunnel']:
                    if self.tunnel_info:
                        # Запускаем асинхронную функцию в отдельном событийном цикле
                        try:
                            asyncio.run(self.connect_to_tunnel())
                        except RuntimeError as e:
                            if "asyncio.run() cannot be called from a running event loop" in str(e):
                                # Если уже запущен event loop, создаем новый
                                loop = asyncio.new_event_loop()
                                asyncio.set_event_loop(loop)
                                loop.run_until_complete(self.connect_to_tunnel())
                                loop.close()
                            else:
                                raise
                    else:
                        print("❌ No tunnel available. Request tunnel first.")
                        
                elif choice in ['6', 'disconnect']:
                    self.disconnect()
                    print("👋 Disconnected from server")
                    break
                    
                elif choice in ['7', 'exit', 'quit']:
                    self.disconnect()
                    print("👋 Goodbye!")
                    break
                    
                else:
                    print("❌ Unknown command")
                    
            except KeyboardInterrupt:
                print("\n👋 Interrupted by user")
                self.disconnect()
                break
            except Exception as e:
                print(f"❌ Error: {e}")
                import traceback
                traceback.print_exc()

    def disconnect(self):
        """Закрывает соединение"""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None

    def auto_mode(self):
        """Автоматический режим - выполняет стандартную последовательность"""
        print("🤖 Starting auto mode...")
        
        if not self.authenticate():
            return

        # Запрашиваем туннель
        print("\n" + "="*30)
        tunnel_info = self.request_tunnel()
        if not tunnel_info:
            return

        # Отправляем ping
        time.sleep(1)
        print("\n" + "="*30)
        self.send_ping()

        # Запрашиваем статус
        time.sleep(1)
        print("\n" + "="*30)
        self.get_status()

        # Отправляем тестовое сообщение
        time.sleep(1)
        print("\n" + "="*30)
        test_message = {
            "text": "Auto-mode test message",
            "type": "auto_test",
            "timestamp": int(time.time()),
            "device_id": self.device_id
        }
        self.send_tunnel_message(test_message)

        print("\n" + "="*30)
        print("✅ Auto mode completed!")
        
        # Предлагаем подключиться к туннелю
        connect = input("\nConnect to WebSocket tunnel? (y/n): ").strip().lower()
        if connect in ['y', 'yes']:
            try:
                asyncio.run(self.connect_to_tunnel())
            except RuntimeError as e:
                if "asyncio.run() cannot be called from a running event loop" in str(e):
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(self.connect_to_tunnel())
                    loop.close()
                else:
                    raise

    def __del__(self):
        """Деструктор для гарантированного закрытия соединений"""
        self.disconnect()

def main():
    client = PSTPClient()
    
    print("PSTP Client - Choose mode:")
    print("1. Interactive mode (recommended)")
    print("2. Auto mode")
    
    try:
        choice = input("Enter choice (1 or 2): ").strip()
        
        if choice == "1":
            client.interactive_mode()
        elif choice == "2":
            client.auto_mode()
        else:
            print("❌ Invalid choice, using interactive mode")
            client.interactive_mode()
            
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        client.disconnect()
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        client.disconnect()

if __name__ == "__main__":
    # Проверяем наличие websockets
    try:
        import websockets
        print("🔧 WebSocket support available")
        main()
    except ImportError:
        print("❌ WebSocket support not available.")
        print("Please install: pip install websockets")
        print("Running in PSTP-only mode...")
        
        client = PSTPClient()
        if client.authenticate():
            client.request_tunnel()
            client.send_ping()
            client.get_status()
        client.disconnect()