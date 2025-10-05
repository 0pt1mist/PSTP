import asyncio
import websockets
import json
import time
import sys

async def test_tunnel():
    token = input("Enter tunnel token: ").strip()
    device_id = input("Enter device ID: ").strip()
    
    uri = f"ws://localhost:8081/tunnel/test?token={token}"
    
    try:
        async with websockets.connect(uri) as websocket:
            print(f"✅ Connected to tunnel for device: {device_id}")
            print("Type messages to send through tunnel (or 'quit' to exit):")
            
            async def receive_messages():
                while True:
                    try:
                        message = await websocket.recv()
                        data = json.loads(message)
                        print(f"\n📨 Received from server: {data}")
                        print("> ", end="", flush=True)
                    except websockets.exceptions.ConnectionClosed:
                        print("\n❌ Connection closed")
                        break
            
            # Запускаем получение сообщений в фоне
            receive_task = asyncio.create_task(receive_messages())
            
            # Основной цикл отправки сообщений
            while True:
                try:
                    message_text = await asyncio.get_event_loop().run_in_executor(
                        None, input, "> "
                    )
                    
                    if message_text.lower() == 'quit':
                        break
                    
                    message = {
                        "device_id": device_id,
                        "message": message_text,
                        "timestamp": time.time(),
                        "type": "test_message"
                    }
                    
                    await websocket.send(json.dumps(message))
                    print(f"📤 Sent: {message_text}")
                    
                except (EOFError, KeyboardInterrupt):
                    break
            
            receive_task.cancel()
            
    except Exception as e:
        print(f"❌ Connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_tunnel())