# UltraDP (Ultra Drop Protocol)
Ultra Fast File Transfer Pipeline 

## DiamondGotCat's Protocols

### UltraDP: Most Fast File Transfer Protocol in My Projects
8 Gbps(1 GB/s) in My Wi-fi

### NextDP(NextDrop): You can use Official Python Library
4.8 Gbps(0.6 GB/s) in My Wi-fi

### USFTP: Built-in File integrity check function (SHA-256)
2 Gbps(0.25 GB/s) in My Wi-fi

## Usage

### Install Requirements

```
pip install kamu-jp-modern aiohttp tqdm zstandard cryptography
```

### Command

```
python nextdrop.py send <target_ip> <file_path> [--threads <num_threads>] [--port <port>]
```

```
python nextdrop.py receive <save_dir> [--compress] [--port <port>]
```
