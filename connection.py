# connection.py — безопасный обмен сообщениями

import threading
import json
import time
import PSTP

def handle_receive(client_socket, encryption_key, mac_key, on_message_callback):
    while True:
        try:
            header_bytes = recv_all(client_socket, PSTP.HEADER_SIZE)
            if not header_bytes:
                break

            mac_bytes = recv_all(client_socket, 16)
            if not mac_bytes:
                break

            header = PSTP.Header.unpack(header_bytes)
            encrypted_data_len = header.PackageLen - header.HeaderLen
            encrypted_data = recv_all(client_socket, encrypted_data_len)
            if not encrypted_data:
                break

            full_packet = header_bytes + encrypted_data + mac_bytes

            try:
                package, plaintext = PSTP.Package.unpack_and_decrypt(
                    full_packet, encryption_key, mac_key
                )
                on_message_callback(plaintext, package.header.DeviceID.decode().strip())
                client_socket.sendall(b'ACK')
            except ValueError as e:
                print(f"Decryption/MAC error: {e}")
                client_socket.sendall(b'NACK')

        except Exception as e:
            print(f"Receive error: {e}")
            break

def handle_send(client_socket, encryption_key, mac_key, device_id, message_queue):
    while True:
        try:
            message = message_queue.get()
            if message is None:
                break

            header = PSTP.Header(
                DeviceID=device_id,
                Nonce=PSTP.Package.generate_nonce(),
                Timestamp=int(time.time())
            )

            package = PSTP.Package(header)
            packed = package.encrypt_and_pack(message, encryption_key, mac_key)

            client_socket.sendall(packed)

            ack = recv_all(client_socket, 4)
            if ack == b'NACK':
                print("Message not acknowledged")

        except Exception as e:
            print(f"Send error: {e}")
            break

def recv_all(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)