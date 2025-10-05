# PSTP.py — Private Secure Transfer Protocol
# Безопасный протокол аутентификации и обмена команд
# Работает поверх TCP, но криптографически независим от транспорта

import struct
import json
import time
import secrets
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# ========================================
# Глобальные константы
# ========================================

HEADER_FORMAT = '!BBH I 16s 8s I H'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
AES_KEY_SIZE = 32
NONCE_SIZE = 12

# ========================================
# Класс заголовка
# ========================================

class Header:
    # Добавляем константу размера заголовка в класс
    HEADER_SIZE = HEADER_SIZE
    
    def __init__(self, Version=1, HeaderLen=HEADER_SIZE, PackageLen=0, ConnectionID=1,
                 DeviceID="", Nonce=b"", Timestamp=0, Reserved=0):
        self.Version = Version
        self.HeaderLen = HeaderLen
        self.PackageLen = PackageLen
        self.ConnectionID = ConnectionID
        # ИСПРАВЛЕНИЕ: корректное кодирование DeviceID
        if isinstance(DeviceID, str):
            self.DeviceID = DeviceID.ljust(16)[:16].encode('utf-8')
        else:
            # Если уже байты, просто обрезаем
            self.DeviceID = DeviceID.ljust(16)[:16] if len(DeviceID) < 16 else DeviceID[:16]
        self.Nonce = Nonce[:8] if len(Nonce) >= 8 else Nonce.ljust(8)[:8]
        self.Timestamp = int(Timestamp)
        self.Reserved = Reserved

    def pack(self):
        return struct.pack(
            HEADER_FORMAT,
            self.Version,
            self.HeaderLen,
            self.PackageLen,
            self.ConnectionID,
            self.DeviceID,
            self.Nonce,
            self.Timestamp,
            self.Reserved
        )

    @classmethod
    def unpack(cls, header_bytes):
        unpacked = struct.unpack(HEADER_FORMAT, header_bytes)
        # ИСПРАВЛЕНИЕ: корректное декодирование DeviceID
        device_id_bytes = unpacked[4]
        try:
            device_id = device_id_bytes.decode('utf-8', errors='ignore').strip('\x00 ')
        except:
            device_id = device_id_bytes.hex()  # fallback
        
        return cls(
            Version=unpacked[0],
            HeaderLen=unpacked[1],
            PackageLen=unpacked[2],
            ConnectionID=unpacked[3],
            DeviceID=device_id,  # Теперь строка
            Nonce=unpacked[5],
            Timestamp=unpacked[6],
            Reserved=unpacked[7]
        )

# ========================================
# Класс пакета
# ========================================

class Package:
    def __init__(self, header, encrypted_data=b"", mac=b""):
        self.header = header
        self.encrypted_data = encrypted_data
        self.mac = mac

    @staticmethod
    def derive_key(shared_secret: bytes, salt: bytes = b'PSTP_AES_SALT') -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            info=b'PSTP Encryption Key',
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)

    @staticmethod
    def calculate_mac(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()[:16]

    def encrypt_and_pack(self, plaintext: str, encryption_key: bytes, mac_key: bytes):
        aes_nonce = secrets.token_bytes(NONCE_SIZE)
        aesgcm = AESGCM(encryption_key)
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = aesgcm.encrypt(aes_nonce, plaintext_bytes, None)

        self.encrypted_data = aes_nonce + ciphertext
        self.header.PackageLen = self.header.HeaderLen + len(self.encrypted_data)

        header_bytes = self.header.pack()
        self.mac = self.calculate_mac(mac_key, header_bytes + self.encrypted_data)

        return header_bytes + self.encrypted_data + self.mac

    @classmethod
    def unpack_and_decrypt(cls, packet_bytes, encryption_key: bytes, mac_key: bytes):
        if len(packet_bytes) < Header.HEADER_SIZE + 16:
            raise ValueError("Packet too short")

        header_bytes = packet_bytes[:Header.HEADER_SIZE]
        mac_received = packet_bytes[-16:]
        encrypted_data = packet_bytes[Header.HEADER_SIZE:-16]

        header = Header.unpack(header_bytes)

        recalculated_mac = cls.calculate_mac(mac_key, header_bytes + encrypted_data)
        if not hmac.compare_digest(mac_received, recalculated_mac):
            raise ValueError("MAC verification failed")

        if len(encrypted_data) < NONCE_SIZE:
            raise ValueError("Ciphertext too short")
        aes_nonce = encrypted_data[:NONCE_SIZE]
        ciphertext = encrypted_data[NONCE_SIZE:]

        aesgcm = AESGCM(encryption_key)
        try:
            plaintext_bytes = aesgcm.decrypt(aes_nonce, ciphertext, None)
            plaintext = plaintext_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

        return cls(header, encrypted_data, mac_received), plaintext

    @staticmethod
    def generate_nonce() -> bytes:
        return secrets.token_bytes(8)

    @staticmethod
    def is_packet_fresh(timestamp: int, ttl_seconds: int = 300) -> bool:
        now = int(time.time())
        return abs(now - timestamp) <= ttl_seconds