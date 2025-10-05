# server_auth.py — безопасная аутентификация устройств

import secrets
import hashlib
import hmac
import time
from typing import Dict, Optional

class DeviceAuthenticator:
    def __init__(self, allowed_devices: Dict[str, bytes]):
        # ИСПРАВЛЕНИЕ: нормализуем ключи словаря
        self.allowed_devices = {}
        for device_id, secret in allowed_devices.items():
            if isinstance(device_id, bytes):
                device_id = device_id.decode('utf-8', errors='ignore').strip()
            elif isinstance(device_id, str):
                device_id = device_id.strip()
            self.allowed_devices[device_id] = secret
        
        self.active_challenges: Dict[bytes, tuple] = {}

    def generate_challenge(self, device_id: str) -> Optional[bytes]:
        # ИСПРАВЛЕНИЕ: нормализуем device_id
        if isinstance(device_id, bytes):
            device_id = device_id.decode('utf-8', errors='ignore').strip()
        elif isinstance(device_id, str):
            device_id = device_id.strip()
            
        print(f"   [Auth] Checking device: '{device_id}'")
        print(f"   [Auth] Allowed devices: {list(self.allowed_devices.keys())}")
        
        if device_id not in self.allowed_devices:
            print(f"   [Auth] ❌ Device '{device_id}' not found in allowed devices")
            return None

        nonce = secrets.token_bytes(16)
        timestamp = int(time.time())
        self.active_challenges[nonce] = (device_id, timestamp)
        print(f"   [Auth] ✅ Challenge generated for '{device_id}'")
        print(f"   [Auth] Challenge: {nonce.hex()} ({len(nonce)} bytes)")
        return nonce

    def verify_response(self, challenge_bytes: bytes, response: str) -> Optional[str]:
        if challenge_bytes not in self.active_challenges:
            print(f"   [Auth] ❌ Challenge not found")
            return None

        device_id, challenge_time = self.active_challenges[challenge_bytes]
        del self.active_challenges[challenge_bytes]

        if time.time() - challenge_time > 300:
            print(f"   [Auth] ❌ Challenge expired")
            return None

        # ВЫЧИСЛЯЕМ HMAC ОТ СЫРЫХ БАЙТОВ CHALLENGE
        expected_hmac = hmac.new(
            self.allowed_devices[device_id],
            challenge_bytes,
            hashlib.sha256
        ).hexdigest()

        print(f"   [Auth] Expected HMAC: {expected_hmac}")
        print(f"   [Auth] Received HMAC: {response}")

        if not hmac.compare_digest(response, expected_hmac):
            print(f"   [Auth] ❌ HMAC mismatch")
            return None

        print(f"   [Auth] ✅ HMAC match for '{device_id}'")
        return device_id