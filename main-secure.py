# UltraDPS (Ultra speed file Drop Protocol Secure)

import asyncio
import socket
import os
import sys
import zstandard as zstd  # zstandard を使用
import argparse
from KamuJpModern.ModernProgressBar import ModernProgressBar  # 進捗バーをインポート
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import getpass
import secrets

CHUNK_SIZE = 1024 * 1024 * 8  # 8MB チャンクサイズを増加
COMPRESSION_LEVEL = 3  # zstd の圧縮レベル
KEY_LENGTH = 32  # AES-256
IV_LENGTH = 16  # 128-bit IV
SALT_LENGTH = 16  # 128-bit Salt
ITERATIONS = 100_000  # PBKDF2 iterations

def derive_key(password: str, salt: bytes) -> bytes:
    """
    パスワードとソルトからAESキーを導出します。
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

class FileSender:
    def __init__(self, target, port, file_path, compress=False, encrypt=False, password=None):
        self.target = target
        self.port = port
        self.file_path = file_path
        self.compress = compress
        self.encrypt = encrypt
        self.password = password
        self.zstd_compressor = zstd.ZstdCompressor(level=COMPRESSION_LEVEL) if self.compress else None
        self.cipher = None
        self.key = None
        self.iv = None

        if self.encrypt:
            if not self.password:
                raise ValueError("Password is required for encryption.")
            self.salt = secrets.token_bytes(SALT_LENGTH)
            self.key = derive_key(self.password, self.salt)
            self.iv = secrets.token_bytes(IV_LENGTH)
            self.cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
            self.encryptor = self.cipher.encryptor()

    async def send_file(self):
        reader, writer = await asyncio.open_connection(self.target, self.port)
        file_size = os.path.getsize(self.file_path)
        filename = os.path.basename(self.file_path)

        # ヘッダー情報: filename:file_size:compress_flag:encrypt_flag
        header = f"{filename}:{file_size}:{int(self.compress)}:{int(self.encrypt)}".encode() + b'\n'
        writer.write(header)
        await writer.drain()

        if self.encrypt:
            # 送信側のソルトとIVを送信
            writer.write(self.salt + self.iv)
            await writer.drain()

        # 進捗バーの設定
        total_chunks = file_size // CHUNK_SIZE + (1 if file_size % CHUNK_SIZE else 0)
        progress_bar = ModernProgressBar(total=total_chunks, process_name="[SEND]", process_color=32)
        progress_bar.start()
        progress_bar.notbusy()

        with open(self.file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                if self.compress:
                    chunk = self.zstd_compressor.compress(chunk)
                if self.encrypt:
                    chunk = self.encryptor.update(chunk)
                writer.write(len(chunk).to_bytes(8, 'big') + chunk)
                await writer.drain()
                progress_bar.update(1)
        if self.encrypt:
            # 暗号化の終了処理
            final_chunk = self.encryptor.finalize()
            if final_chunk:
                writer.write(len(final_chunk).to_bytes(8, 'big') + final_chunk)
                await writer.drain()
        writer.close()
        await writer.wait_closed()
        progress_bar.finish()
        print("[DONE]")

class FileReceiver:
    def __init__(self, port, save_dir, encrypt=False, password=None):
        self.port = port
        self.save_dir = save_dir
        self.encrypt = encrypt
        self.password = password
        self.decompressor = zstd.ZstdDecompressor() if self.encrypt else None
        self.cipher = None
        self.key = None
        self.iv = None

    async def start_server(self):
        server = await asyncio.start_server(self.handle_client, '0.0.0.0', self.port)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        print(f"[<==>] {addrs}")
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader, writer):
        try:
            header = await reader.readline()
            filename, file_size, compress_flag, encrypt_flag = header.decode().strip().split(':')
            file_size = int(file_size)
            compress_flag = bool(int(compress_flag))
            encrypt_flag = bool(int(encrypt_flag))
            save_path = os.path.join(self.save_dir, filename)
            decompressor = zstd.ZstdDecompressor() if compress_flag else None

            if encrypt_flag:
                # ソルトとIVの受信
                salt = await reader.readexactly(SALT_LENGTH)
                iv = await reader.readexactly(IV_LENGTH)
                if not self.password:
                    raise ValueError("Password is required for decryption.")
                key = derive_key(self.password, salt)
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()

            # 進捗バーの設定
            total_chunks = file_size // CHUNK_SIZE + (1 if file_size % CHUNK_SIZE else 0)
            progress_bar = ModernProgressBar(total=total_chunks, process_name="[RECV]", process_color=32)
            progress_bar.start()
            progress_bar.notbusy()

            with open(save_path, 'wb') as f:
                received = 0
                while received < file_size:
                    # チャンクサイズを受信
                    chunk_size_data = await reader.readexactly(8)
                    chunk_size = int.from_bytes(chunk_size_data, 'big')
                    # チャンクデータを受信
                    chunk = await reader.readexactly(chunk_size)
                    if encrypt_flag:
                        chunk = decryptor.update(chunk)
                    if compress_flag:
                        chunk = decompressor.decompress(chunk)
                    f.write(chunk)
                    received += chunk_size  # 圧縮後のサイズを加算
                    progress_bar.update(1)
                if encrypt_flag:
                    # 復号化の終了処理
                    final_chunk = decryptor.finalize()
                    if final_chunk:
                        f.write(final_chunk)
            progress_bar.finish()
            print(f"[DONE] {filename}")
        except Exception as e:
            print(f"[ERR ] {e}")
        finally:
            writer.close()
            await writer.wait_closed()

def get_local_ip():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)

async def main():
    parser = argparse.ArgumentParser(description="High-Speed Secure Data Pipeline")
    subparsers = parser.add_subparsers(dest='mode', help='send/receive')

    # 送信モードの引数
    send_parser = subparsers.add_parser('send', help='Send File')
    send_parser.add_argument('target', type=str, help='IP Address of Target', default='127.0.0.1')
    send_parser.add_argument('--port', type=int, help='Port of Target', default=4321)
    send_parser.add_argument('file_path', type=str, help='File Path')
    send_parser.add_argument('--compress', action='store_true', help='Compress Mode')
    send_parser.add_argument('--encrypt', action='store_true', help='Encrypt Mode')
    send_parser.add_argument('--password', type=str, help='Password for Encryption (optional)')

    # 受信モードの引数
    receive_parser = subparsers.add_parser('receive', help='Receive File')
    receive_parser.add_argument('--port', type=int, help='Port', default=4321)
    receive_parser.add_argument('save_dir', type=str, help='Save Directory')
    receive_parser.add_argument('--encrypt', action='store_true', help='Decrypt Mode')
    receive_parser.add_argument('--password', type=str, help='Password for Decryption (optional)')

    args = parser.parse_args()

    if args.mode == 'send':
        if not os.path.isfile(args.file_path):
            print(f"[ERR ] FILE-NOTFOUND: '{args.file_path}'")
            sys.exit(1)
        password = args.password
        if args.encrypt and not password:
            password = getpass.getpass(prompt='Enter password for encryption: ')
        sender = FileSender(
            target=args.target,
            port=args.port,
            file_path=args.file_path,
            compress=args.compress,
            encrypt=args.encrypt,
            password=password
        )
        await sender.send_file()
    elif args.mode == 'receive':
        if not os.path.isdir(args.save_dir):
            print(f"[ERR ] DIRECTORY-NOTFOUND: '{args.save_dir}'")
            sys.exit(1)
        password = args.password
        if args.encrypt and not password:
            password = getpass.getpass(prompt='Enter password for decryption: ')
        receiver = FileReceiver(
            port=args.port,
            save_dir=args.save_dir,
            encrypt=args.encrypt,
            password=password
        )
        await receiver.start_server()
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[WARN] KEY-EXIT")
