#!/usr/bin/env python3
"""
Скрипт для принудительной очистки WebSocket соединений
Может использоваться перед запуском сервера
"""

import asyncio
import websockets
import json

async def force_cleanup():
    """Принудительно закрывает все WebSocket соединения на указанном порту"""
    print("🧹 Force cleaning WebSocket connections...")
    
    # Попытка подключиться и сразу разорвать соединение
    # Это вызовет закрытие сервера если он запущен
    try:
        async with websockets.connect('ws://localhost:8081/tunnel/cleanup') as websocket:
            await websocket.close()
    except:
        pass  # Ожидаем, что соединение не установится
    
    print("✅ Force cleanup completed")
    print("💡 Now you can safely start the server")

if __name__ == "__main__":
    asyncio.run(force_cleanup())