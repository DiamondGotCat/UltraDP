# UltraDPS (Ultra speed file Drop Protocol Secure)

import asyncio
import socket
import os
import sys
import zstandard as zstd  # zstandard を使用
import argparse
from KamuJpModern.ModernProgressBar import ModernProgressBar  # 進捗バーをインポート

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK_SIZE = 1024 * 1024 * 8  # 8MB チャンクサイズを増加
COMPRESSION_LEVEL = 3  # zstd の圧縮レベル

# ヘルパー関数: メッセージを送信（長さプレフィックス付き）
async def send_message(writer, message: bytes):
    writer.write(len(message).to_bytes(4, 'big') + message)
    await writer.drain()

# ヘルパー関数: メッセージを受信（長さプレフィックス付き）
async def receive_message(reader) -> bytes:
    length_data = await reader.readexactly(4)
    length = int.from_bytes(length_data, 'big')
    message = await reader.readexactly(length)
    return message

class FileSender:
    def __init__(self, target, port, file_path, compress=False):
        self.target = target
        self.port = port
        self.file_path = file_path
        self.compress = compress
        self.zstd_compressor = zstd.ZstdCompressor(level=COMPRESSION_LEVEL) if self.compress else None

    async def send_file(self):
        reader, writer = await asyncio.open_connection(self.target, self.port)
        try:
            # 1. キー交換プロセス
            # 1.1 受信側の公開鍵を受信
            receiver_public_key_bytes = await receive_message(reader)
            receiver_public_key = serialization.load_pem_public_key(receiver_public_key_bytes)

            # 1.2 自分の公開鍵を生成して送信
            sender_private_key = ec.generate_private_key(ec.SECP384R1())
            sender_public_key = sender_private_key.public_key()
            sender_public_key_bytes = sender_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            await send_message(writer, sender_public_key_bytes)

            # 1.3 共有鍵の生成と対称鍵の導出
            shared_secret = sender_private_key.exchange(ec.ECDH(), receiver_public_key)
            symmetric_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'UltraDPS key derivation'
            ).derive(shared_secret)
            aesgcm = AESGCM(symmetric_key)

            # 2. ヘッダーの準備と暗号化
            file_size = os.path.getsize(self.file_path)
            filename = os.path.basename(self.file_path)
            header = f"{filename}:{file_size}:{int(self.compress)}".encode()
            nonce = os.urandom(12)
            encrypted_header = aesgcm.encrypt(nonce, header, None)
            # 送信するメッセージ: nonce + ciphertext
            encrypted_header_message = nonce + encrypted_header
            await send_message(writer, encrypted_header_message)

            # 3. 進捗バーの設定
            total_chunks = file_size // CHUNK_SIZE + (1 if file_size % CHUNK_SIZE else 0)
            progress_bar = ModernProgressBar(total=total_chunks, process_name="[SEND]", process_color=32)
            progress_bar.start()
            progress_bar.notbusy()

            # 4. ファイルの送信
            with open(self.file_path, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    if self.compress:
                        chunk = self.zstd_compressor.compress(chunk)
                    nonce = os.urandom(12)
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    encrypted_message = nonce + encrypted_chunk
                    await send_message(writer, encrypted_message)
                    progress_bar.update(1)

            writer.close()
            await writer.wait_closed()
            progress_bar.finish()
            print("[DONE]")
        except Exception as e:
            print(f"[ERR ] {e}")
            writer.close()
            await writer.wait_closed()

class FileReceiver:
    def __init__(self, port, save_dir):
        self.port = port
        self.save_dir = save_dir

    async def start_server(self):
        server = await asyncio.start_server(self.handle_client, '0.0.0.0', self.port)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        print(f"[<==>] {addrs}")
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader, writer):
        try:
            # 1. キー交換プロセス
            # 1.1 送信側の公開鍵を受信
            sender_public_key_bytes = await receive_message(reader)
            sender_public_key = serialization.load_pem_public_key(sender_public_key_bytes)

            # 1.2 自分の公開鍵を生成して送信
            receiver_private_key = ec.generate_private_key(ec.SECP384R1())
            receiver_public_key = receiver_private_key.public_key()
            receiver_public_key_bytes = receiver_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            await send_message(writer, receiver_public_key_bytes)

            # 1.3 共有鍵の生成と対称鍵の導出
            shared_secret = receiver_private_key.exchange(ec.ECDH(), sender_public_key)
            symmetric_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'UltraDPS key derivation'
            ).derive(shared_secret)
            aesgcm = AESGCM(symmetric_key)

            # 2. ヘッダーの受信と復号化
            encrypted_header_message = await receive_message(reader)
            nonce = encrypted_header_message[:12]
            ciphertext = encrypted_header_message[12:]
            header = aesgcm.decrypt(nonce, ciphertext, None)
            filename, file_size, compress_flag = header.decode().strip().split(':')
            file_size = int(file_size)
            compress_flag = bool(int(compress_flag))
            save_path = os.path.join(self.save_dir, filename)
            decompressor = zstd.ZstdDecompressor() if compress_flag else None

            # 3. 進捗バーの設定
            total_chunks = file_size // CHUNK_SIZE + (1 if file_size % CHUNK_SIZE else 0)
            progress_bar = ModernProgressBar(total=total_chunks, process_name="[RECV]", process_color=32)
            progress_bar.start()
            progress_bar.notbusy()

            # 4. ファイルの受信と復号化
            with open(save_path, 'wb') as f:
                received = 0
                while received < file_size:
                    encrypted_chunk_message = await receive_message(reader)
                    nonce = encrypted_chunk_message[:12]
                    ciphertext = encrypted_chunk_message[12:]
                    chunk = aesgcm.decrypt(nonce, ciphertext, None)
                    if compress_flag:
                        chunk = decompressor.decompress(chunk)
                    f.write(chunk)
                    received += len(chunk)  # 圧縮後のサイズを加算
                    progress_bar.update(1)
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
    parser = argparse.ArgumentParser(description="High-Speed Data Pipeline Secure")
    subparsers = parser.add_subparsers(dest='mode', help='send/receive')

    # 送信モードの引数
    send_parser = subparsers.add_parser('send', help='Send File Securely')
    send_parser.add_argument('target', type=str, help='IP Address of Target', default='127.0.0.1')
    send_parser.add_argument('--port', type=int, help='Port of Target', default=4321)
    send_parser.add_argument('file_path', type=str, help='File Path')
    send_parser.add_argument('--compress', action='store_true', help='Compress Mode')

    # 受信モードの引数
    receive_parser = subparsers.add_parser('receive', help='Receive File Securely')
    receive_parser.add_argument('--port', type=int, help='Port', default=4321)
    receive_parser.add_argument('save_dir', type=str, help='Save Directory')

    args = parser.parse_args()

    if args.mode == 'send':
        if not os.path.isfile(args.file_path):
            print(f"[ERR ] FILE-NOTFOUND: '{args.file_path}'")
            sys.exit(1)
        sender = FileSender(args.target, args.port, args.file_path, args.compress)
        await sender.send_file()
    elif args.mode == 'receive':
        if not os.path.isdir(args.save_dir):
            print(f"[ERR ] DIRECTORY-NOTFOUND: '{args.save_dir}'")
            sys.exit(1)
        receiver = FileReceiver(args.port, args.save_dir)
        await receiver.start_server()
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[WARN] KEY-EXIT")
