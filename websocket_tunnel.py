import asyncio
import websockets
import json
import time
import secrets
from typing import Dict, Set
import logging

class WebSocketTunnel:
    def __init__(self, host='localhost', port=8081):
        self.host = host
        self.port = port
        self.connections: Dict[str, websockets.WebSocketServerProtocol] = {}
        self.tokens: Dict[str, dict] = {}  # token -> device_info
        self.message_queue = asyncio.Queue()
        self.server = None
        self._cleanup_task = None
        
    async def cleanup_existing_connections(self):
        """Очищает все активные соединения при запуске"""
        print("🧹 Cleaning up existing WebSocket connections...")
        
        # Закрываем все активные соединения
        devices_to_remove = []
        for device_id, websocket in self.connections.items():
            try:
                if not websocket.closed:
                    await websocket.close(code=1000, reason="Server restart")
                    print(f"   ✅ Closed connection for device: {device_id}")
            except Exception as e:
                print(f"   ❌ Error closing connection for {device_id}: {e}")
            devices_to_remove.append(device_id)
        
        # Очищаем словарь соединений
        for device_id in devices_to_remove:
            if device_id in self.connections:
                del self.connections[device_id]
        
        # Очищаем токены
        self.tokens.clear()
        print("✅ All existing connections cleaned up")
    
    def generate_tunnel(self, device_id: str) -> dict:
        """Генерирует новый туннель для устройства"""
        token = secrets.token_urlsafe(16)
        tunnel_id = secrets.token_urlsafe(8)
        
        tunnel_info = {
            'device_id': device_id,
            'token': token,
            'tunnel_url': f'wss://{self.host}:{self.port}/tunnel/{tunnel_id}',
            'created_at': time.time(),
            'expires_at': time.time() + 3600
        }
        
        self.tokens[token] = tunnel_info
        return tunnel_info
    
    def verify_token(self, token: str) -> bool:
        """Проверяет валидность токена"""
        if token not in self.tokens:
            return False
            
        tunnel_info = self.tokens[token]
        if time.time() > tunnel_info['expires_at']:
            del self.tokens[token]
            return False
            
        return True
    
    async def handle_websocket(self, websocket, path):
        """Обрабатывает WebSocket соединения"""
        client_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
        print(f"🔗 New WebSocket connection from {client_ip}, path: {path}")
        
        try:
            # Извлекаем токен из query параметров или заголовков
            token = None
            
            # Проверяем query параметры
            if '?' in path:
                path_parts = path.split('?')
                if len(path_parts) > 1:
                    from urllib.parse import parse_qs
                    query_params = parse_qs(path_parts[1])
                    token = query_params.get('token', [None])[0]
            
            # Проверяем заголовки Authorization
            if not token and websocket.request_headers.get('Authorization'):
                auth_header = websocket.request_headers['Authorization']
                if auth_header.startswith('Bearer '):
                    token = auth_header[7:]
            
            if not token:
                await websocket.close(1008, "Token required")
                print(f"   ❌ Connection rejected: no token from {client_ip}")
                return
            
            if not self.verify_token(token):
                await websocket.close(1008, "Invalid or expired token")
                print(f"   ❌ Connection rejected: invalid token from {client_ip}")
                return
            
            tunnel_info = self.tokens[token]
            device_id = tunnel_info['device_id']
            
            # Закрываем предыдущее соединение для этого устройства, если есть
            if device_id in self.connections:
                old_websocket = self.connections[device_id]
                if not old_websocket.closed:
                    try:
                        await old_websocket.close(code=1000, reason="New connection from same device")
                        print(f"   🔄 Closed previous connection for device: {device_id}")
                    except Exception as e:
                        print(f"   ⚠️ Error closing previous connection: {e}")
            
            # Регистрируем новое соединение
            self.connections[device_id] = websocket
            print(f"   ✅ WebSocket tunnel connected: {device_id} from {client_ip}")
            
            try:
                # Отправляем приветственное сообщение
                welcome_msg = {
                    'status': 'connected',
                    'device_id': device_id,
                    'timestamp': time.time(),
                    'message': 'WebSocket tunnel established'
                }
                await websocket.send(json.dumps(welcome_msg))
                
                # Основной цикл обработки сообщений
                async for message in websocket:
                    try:
                        message_data = json.loads(message)
                        await self.message_queue.put({
                            'type': 'from_tunnel',
                            'device_id': device_id,
                            'data': message_data,
                            'timestamp': time.time(),
                            'client_ip': client_ip
                        })
                        
                        # Автоматический ответ для отладки
                        response = {
                            'status': 'delivered',
                            'original_message': message_data,
                            'timestamp': time.time(),
                            'server_note': 'Message received by server'
                        }
                        await websocket.send(json.dumps(response))
                        
                    except json.JSONDecodeError:
                        error_msg = {
                            'error': 'Invalid JSON', 
                            'timestamp': time.time()
                        }
                        await websocket.send(json.dumps(error_msg))
                        print(f"   ❌ Invalid JSON from {device_id}")
                        
            except websockets.exceptions.ConnectionClosed as e:
                print(f"   🔌 WebSocket tunnel disconnected: {device_id}, code: {e.code}, reason: {e.reason}")
            except Exception as e:
                print(f"   ❌ WebSocket error for {device_id}: {e}")
            finally:
                # Удаляем из активных соединений только если это текущее соединение
                if device_id in self.connections and self.connections[device_id] == websocket:
                    del self.connections[device_id]
                    print(f"   🗑️ Removed {device_id} from active connections")
                    
        except Exception as e:
            print(f"❌ WebSocket setup error: {e}")
    
    async def send_to_device(self, device_id: str, message: dict):
        """Отправляет сообщение устройству через WebSocket"""
        if device_id in self.connections:
            websocket = self.connections[device_id]
            try:
                if not websocket.closed:
                    await websocket.send(json.dumps(message))
                    print(f"   📤 Sent message to {device_id}: {message.get('type', 'unknown')}")
                    return True
                else:
                    print(f"   ❌ WebSocket closed for {device_id}")
                    # Удаляем закрытое соединение
                    del self.connections[device_id]
                    return False
            except Exception as e:
                print(f"   ❌ Failed to send to {device_id}: {e}")
                # Удаляем проблемное соединение
                if device_id in self.connections:
                    del self.connections[device_id]
                return False
        else:
            print(f"   ❌ No active WebSocket connection for {device_id}")
            return False
    
    async def broadcast_message(self, message: dict, exclude_devices: set = None):
        """Отправляет сообщение всем подключенным устройствам"""
        if exclude_devices is None:
            exclude_devices = set()
            
        successful = 0
        failed = 0
        devices_to_remove = []
        
        for device_id, websocket in self.connections.items():
            if device_id in exclude_devices:
                continue
                
            try:
                if not websocket.closed:
                    await websocket.send(json.dumps(message))
                    successful += 1
                else:
                    devices_to_remove.append(device_id)
                    failed += 1
            except Exception:
                devices_to_remove.append(device_id)
                failed += 1
        
        # Удаляем проблемные соединения
        for device_id in devices_to_remove:
            if device_id in self.connections:
                del self.connections[device_id]
        
        if successful > 0 or failed > 0:
            print(f"   📢 Broadcast: {successful} successful, {failed} failed")
    
    async def debug_loop(self):
        """Цикл отладки для вывода сообщений в консоль"""
        while True:
            try:
                message = await asyncio.wait_for(self.message_queue.get(), timeout=1.0)
                
                if message['type'] == 'from_tunnel':
                    print(f"📨 [TUNNEL → SERVER] Device: {message['device_id']}")
                    print(f"    IP: {message.get('client_ip', 'unknown')}")
                    print(f"    Data: {json.dumps(message['data'], indent=4)}")
                    print(f"    Time: {time.ctime(message['timestamp'])}")
                    print("    " + "-" * 50)
                    
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"❌ Debug loop error: {e}")
    
    async def connection_monitor(self):
        """Мониторинг активных соединений"""
        while True:
            try:
                active_count = len(self.connections)
                if active_count > 0:
                    print(f"   📊 Active WebSocket connections: {active_count}")
                    print(f"   📋 Connected devices: {list(self.connections.keys())}")
                
                await asyncio.sleep(30)  # Отчет каждые 30 секунд
                
            except Exception as e:
                print(f"❌ Connection monitor error: {e}")
                await asyncio.sleep(30)
    
    async def start(self):
        """Запускает WebSocket сервер"""
        print(f"🌐 WebSocket tunnel server starting on {self.host}:{self.port}")
        
        # Очищаем существующие соединения
        await self.cleanup_existing_connections()
        
        # Запускаем цикл отладки
        debug_task = asyncio.create_task(self.debug_loop())
        
        # Запускаем мониторинг соединений
        monitor_task = asyncio.create_task(self.connection_monitor())
        
        # Запускаем WebSocket сервер
        try:
            self.server = await websockets.serve(
                self.handle_websocket, 
                self.host, 
                self.port,
                ping_interval=20,  # Ping каждые 20 секунд
                ping_timeout=10,   # Таймаут ping 10 секунд
                close_timeout=10   # Таймаут закрытия 10 секунд
            )
            
            print(f"✅ WebSocket tunnel server ready on ws://{self.host}:{self.port}")
            print("   🎯 Server will clean up existing connections on startup")
            print("   🔄 Duplicate device connections will be automatically handled")
            
            # Бесконечное ожидание
            await asyncio.Future()
            
        except Exception as e:
            print(f"❌ Failed to start WebSocket server: {e}")
        finally:
            # Отменяем задачи при завершении
            debug_task.cancel()
            monitor_task.cancel()
            try:
                await debug_task
                await monitor_task
            except asyncio.CancelledError:
                pass
    
    async def stop(self):
        """Останавливает WebSocket сервер и закрывает все соединения"""
        print("🛑 Stopping WebSocket tunnel server...")
        
        # Закрываем все соединения
        await self.cleanup_existing_connections()
        
        # Останавливаем сервер
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print("✅ WebSocket server stopped")

# Синглтон для доступа из других модулей
tunnel_server = WebSocketTunnel()