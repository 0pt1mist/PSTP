# server_auth.py — безопасная аутентификация устройств

import secrets
import hashlib
import hmac
import time
from typing import Dict, Optional

class DeviceAuthenticator:
    def __init__(self, allowed_devices: Dict[str, bytes]):
        self.allowed_devices = allowed_devices
        self.active_challenges: Dict[bytes, tuple] = {}  # ← Ключ — сырые байты, не hex

    def generate_challenge(self, device_id: str) -> Optional[bytes]:
        print(f"   [Auth] Checking device: {device_id}")
        print(f"   [Auth] Allowed devices: {list(self.allowed_devices.keys())}")
        device_id = device_id.strip()
        if device_id not in self.allowed_devices:
            print(f"   [Auth] ❌ Device {device_id} not allowed")
            return None

        nonce = secrets.token_bytes(16)
        timestamp = int(time.time())
        self.active_challenges[nonce] = (device_id, timestamp)  # ← Сохраняем сырые байты
        print(f"   [Auth] ✅ Challenge generated for {device_id}")
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
            challenge_bytes,  # ← СЫРЫЕ БАЙТЫ, НЕ hex
            hashlib.sha256
        ).hexdigest()

        print(f"   [Auth] Expected HMAC: {expected_hmac}")
        print(f"   [Auth] Received HMAC: {response}")

        if not hmac.compare_digest(response, expected_hmac):
            print(f"   [Auth] ❌ HMAC mismatch")
            return None

        print(f"   [Auth] ✅ HMAC match")
        return device_id