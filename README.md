🌐 PSTP — Private Secure Transfer Protocol
Your personal digital key — to any device, anywhere, without clouds, without intermediaries.

🎯 What is it?
PSTP is your own, secure, closed protocol for communication between your devices.

Imagine:

You approach your home — and your phone whispers to your server: “It's me. Give me access.”
The server checks — and opens the door. Not for everyone. Just for you.
You sit down at your laptop in a cafe — and tell your PC at home: “Turn on the camera. I'll check if everything is ok.”
No one will eavesdrop. No one will connect for you. Just you — and your devices.

It's not magic. It's PSTP.

🔐 Why is it special?
✅ No open-text passwords. Just a cryptographic handshake.
✅ No clouds. Your data is yours alone.
✅ No standards you don't control. It's your protocol. You decide how it works.
✅ Works everywhere: on your phone, on your PC, on your Raspberry Pi, on your ESP32, in IoT, on servers, in P2P networks.
✅ You are the boss. You decide who can connect. When. And why.

🚀 How it works — in 3 steps
Step 1: You say: “It's me”
Your device (phone, laptop, sensor) connects to the server and receives a random challenge from it — like a riddle password.

Step 2: You answer correctly — and only you know how
You calculate the cryptographic fingerprint of this challenge — using a shared secret that only you know. Send the answer. The server checks — and if everything matches — you're through.

Step 3: You get the key to the door
The server gives you a temporary token and a secure channel address — WebSocket, MQTT, tunnel — whatever.
Now you can control anything: turn on the light, get a file, watch the camera, reboot the server — whatever you allowed.



💡 Where can you use it?
🏠 Smart home — turn on the kettle while you're driving home.
🖥️ Remote access — get the server console from anywhere in the world.
📱 Mobile apps — get data without Firebase and Google.
📡 IoT devices — let your sensor listen only to you.
🔁 P2P sharing — transfer files between your phone and laptop — without clouds.
🛡️ Emergency channel — when everything is down — PSTP still works.

# Launch the server on your PC
python server.py

# Connect from your phone
python client.py

→ 🔑 Received challenge: a1b2c3...
→ 🤝 Response sent: 9f8e7d...
→ ✅ Authentication successful!
→ 🚪 Received token: xyz789
→ 🌐 Connecting to: wss://home.local/tunnel/xyz789

🎉 Done. Now you control everything.

🛠️ How to get started?

Clone the repository.

Install dependencies: pip install cryptography

Configure MainConf.conf — specify DeviceID and shared secret.

Start the server → start the client → get access.


🧭 Philosophy

Technology should work for you — not you for it.

PSTP v2 is not “another protocol”.

It’s your personal digital lock.

You choose who to open the door to.

And when to close it.


📜 License

MIT — do what you want. Modify. Distribute. Use everywhere.



