# instructions.py — безопасное чтение конфигурации

import os

CONFIG_FILE = 'MainConf.conf'

def read_device_config(file_path=CONFIG_FILE):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Config file {file_path} not found")

    with open(file_path, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]

    if len(lines) < 2:
        raise ValueError("Config file must have at least 2 lines: DeviceID and SharedSecret")

    device_id = lines[0]
    shared_secret = lines[1].encode('utf-8')

    return device_id, shared_secret

def read_server_allowed_devices(file_path=CONFIG_FILE):
    device_secrets = {}
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for line in lines[2:]:
        line = line.strip()
        if ':' in line:
            device_id, secret = line.split(':', 1)
            device_secrets[device_id.strip()] = secret.encode('utf-8')

    return device_secrets