# UltraDP (Ultra Drop Protocol)
Ultra Fast File Transfer Pipeline 

## My Pipelines Ranking

### 1. UltraDP
Most Fast in My Project.
**PEEK SPEED:** 2.5GB / 3sec

### 2. FastDP | NextDP(NextDrop)
**PEEK SPEED:** 3GB / 5sec

## Usage

### Install Requirements

```
pip install kamu-jp-modern aiohttp tqdm zstandard
```

### Command

```
python nextdrop.py send <target_ip> --port <port> <file_path> [--threads <num_threads>]
```

```
python nextdrop.py receive --port <port> <save_dir> [--compress]
```
