# UltraDP(Ultra speed file Drop Protocol)

import asyncio
import socket
import os
import sys
import zstandard as zstd  # zstandard を使用
import argparse
from KamuJpModern.ModernProgressBar import ModernProgressBar  # 進捗バーをインポート

CHUNK_SIZE = 1024 * 1024 * 8  # 8MB チャンクサイズを増加
COMPRESSION_LEVEL = 3  # zstd の圧縮レベル

class FileSender:
    def __init__(self, target, port, file_path, compress=False):
        self.target = target
        self.port = port
        self.file_path = file_path
        self.compress = compress
        self.zstd_compressor = zstd.ZstdCompressor(level=COMPRESSION_LEVEL) if self.compress else None

    async def send_file(self):
        reader, writer = await asyncio.open_connection(self.target, self.port)
        file_size = os.path.getsize(self.file_path)
        filename = os.path.basename(self.file_path)

        # ファイル名とサイズを最初に送信
        header = f"{filename}:{file_size}:{int(self.compress)}".encode() + b'\n'
        writer.write(header)
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
                writer.write(len(chunk).to_bytes(8, 'big') + chunk)
                await writer.drain()
                progress_bar.update(1)
        writer.close()
        await writer.wait_closed()
        progress_bar.finish()
        print("[DONE]")

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
            header = await reader.readline()
            filename, file_size, compress_flag = header.decode().strip().split(':')
            file_size = int(file_size)
            compress_flag = bool(int(compress_flag))
            save_path = os.path.join(self.save_dir, filename)
            decompressor = zstd.ZstdDecompressor() if compress_flag else None

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
                    if compress_flag:
                        chunk = decompressor.decompress(chunk)
                    f.write(chunk)
                    received += chunk_size  # 圧縮後のサイズを加算
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
    parser = argparse.ArgumentParser(description="High-Speed Data Pipeline")
    subparsers = parser.add_subparsers(dest='mode', help='send/receive')

    # 送信モードの引数
    send_parser = subparsers.add_parser('send', help='Send File')
    send_parser.add_argument('target', type=str, help='IP Address of Target', default='127.0.0.1')
    send_parser.add_argument('--port', type=int, help='Port of Target', default=4321)
    send_parser.add_argument('file_path', type=str, help='File Path')
    send_parser.add_argument('--compress', action='store_true', help='Compress Mode')

    # 受信モードの引数
    receive_parser = subparsers.add_parser('receive', help='Receive File')
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
            print(f"[ERR ] DIRECTRY-NOTFOUND: '{args.save_dir}'")
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
