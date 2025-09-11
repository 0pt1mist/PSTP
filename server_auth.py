# server_auth.py — безопасная аутентификация устройств

import secrets
import hashlib
import hmac
import time
from typing import Dict, Optional

class DeviceAuthenticator:
    def __init__(self, allowed_devices: Dict[str, bytes]):
        self.allowed_devices = allowed_devices
        self.active_challenges: Dict[str, tuple] = {}

    def generate_challenge(self, device_id: str) -> Optional[bytes]:
        if device_id not in self.allowed_devices:
            return None

        nonce = secrets.token_bytes(16)
        timestamp = int(time.time())
        self.active_challenges[nonce.hex()] = (device_id, timestamp)
        return nonce

    def verify_response(self, challenge_nonce: str, response: str) -> Optional[str]:
        if challenge_nonce not in self.active_challenges:
            return None

        device_id, challenge_time = self.active_challenges[challenge_nonce]
        del self.active_challenges[challenge_nonce]

        if time.time() - challenge_time > 300:
            return None

        expected_hmac = hmac.new(
            self.allowed_devices[device_id],
            challenge_nonce.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(response, expected_hmac):
            return None

        return device_id