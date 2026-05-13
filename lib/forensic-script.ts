export const FORENSIC_SCRIPT = `#!/usr/bin/env python3
import os
import sys
import json
import uuid
import stat
import zipfile
import hashlib
import platform
import argparse
import mimetypes
import concurrent.futures
import multiprocessing
from datetime import datetime, timezone
import math
from collections import defaultdict

# Try to import pyarrow for native Parquet emission
try:
    import pyarrow as pa
    import pyarrow.parquet as pq
    PARQUET_AVAILABLE = True
except ImportError:
    PARQUET_AVAILABLE = False

# macOS System & Noisy Directories Skip-List
SKIP_DIRS = {
    '.Spotlight-V100', '.fseventsd', '.DocumentRevisions-V100', 
    '.PKInstallSandboxManager', '.Trashes', '.TemporaryItems'
}

def get_tooling(filename):
    ext = os.path.splitext(filename)[1].lower()
    tooling = {
        '.py': 'Python', '.rs': 'Rust', '.js': 'JavaScript', '.ts': 'TypeScript',
        '.html': 'HTML', '.css': 'CSS', '.c': 'C', '.cpp': 'C++', '.go': 'Go',
        '.sh': 'Shell', '.json': 'JSON', '.toml': 'TOML', '.yaml': 'YAML', '.yml': 'YAML',
        '.sql': 'SQL', '.md': 'Markdown', '.rb': 'Ruby', '.php': 'PHP', '.java': 'Java',
        '.swift': 'Swift', '.kt': 'Kotlin', '.zig': 'Zig', '.h': 'C/C++ Header',
        '.csv': 'CSV', '.txt': 'Text'
    }
    return tooling.get(ext, 'Unknown')

def calculate_entropy(filepath, chunk_size=65536, max_bytes=1048576):
    """Calculates Shannon entropy on the first 1MB of a file to detect packed/encrypted data."""
    try:
        byte_counts = [0] * 256
        total_bytes = 0
        with open(filepath, 'rb') as f:
            while chunk := f.read(chunk_size):
                for byte in chunk:
                    byte_counts[byte] += 1
                total_bytes += len(chunk)
                if total_bytes >= max_bytes:
                    break
        
        if total_bytes == 0: return 0.0
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
        return round(entropy, 4)
    except Exception:
        return None

def hash_file(filepath, max_hash_size, chunk_size=8192):
    """Generates SHA256, throttling/skipping massive files to prevent I/O lockup."""
    try:
        file_size = os.path.getsize(filepath)
        if file_size > max_hash_size:
            return "SKIPPED_LARGE_FILE"
            
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return "HASH_ERROR"

def process_file_worker(args_tuple):
    """Worker function optimized for ProcessPoolExecutor."""
    file_path, file_name, args_no_hash, args_max_hash_size, args_entropy = args_tuple
    try:
        entry_stat = os.lstat(file_path)
        size = entry_stat.st_size
        
        created_ts = getattr(entry_stat, 'st_birthtime', entry_stat.st_ctime)
        modified_ts = entry_stat.st_mtime
        
        file_data = {
            'id': str(uuid.uuid4()),
            'path': file_path,
            'filename': file_name,
            'size': size,
            'created': datetime.fromtimestamp(created_ts, tz=timezone.utc).isoformat(),
            'modified': datetime.fromtimestamp(modified_ts, tz=timezone.utc).isoformat(),
            'permissions': stat.filemode(entry_stat.st_mode),
            'uid': entry_stat.st_uid,
            'gid': entry_stat.st_gid,
            'inode': entry_stat.st_ino,
            'device': entry_stat.st_dev,
            'mime': mimetypes.guess_type(file_name)[0] or 'application/octet-stream',
            'lang': get_tooling(file_name),
            'sha256': None,
            'entropy': None
        }

        if not args_no_hash:
            file_data['sha256'] = hash_file(file_path, args_max_hash_size)
            
        if args_entropy and size > 0:
            file_data['entropy'] = calculate_entropy(file_path)

        return file_data, None
    except Exception as e:
        return None, {'path': file_path, 'error': str(e)}

def compute_directory_sizes(files_manifest):
    """Aggregates recursive directory sizes from file entries."""
    dir_sizes = defaultdict(lambda: {"count": 0, "size": 0})
    for f in files_manifest:
        # compute all parent directories
        parent = os.path.dirname(f['path'])
        size = f['size']
        while parent:
            dir_sizes[parent]["count"] += 1
            dir_sizes[parent]["size"] += size
            old_parent = parent
            parent = os.path.dirname(parent)
            if old_parent == parent: break
    
    # Convert back to standard dict
    return dict(dir_sizes)

def scan_volume(root_path, args):
    scan_id = str(uuid.uuid4())
    metadata = {
        'scan_id': scan_id,
        'volume_name': args.volume_name,
        'hostname': platform.node(),
        'platform': platform.platform(),
        'root_path': root_path,
        'start_time': datetime.now(timezone.utc).isoformat(),
        'end_time': None,
        'total_files': 0,
        'total_size': 0,
        'file_type_statistics': {},
        'directory_sizes': {}
    }
    
    files_manifest = []
    errors = []
    
    # Aggregator for file types
    type_stats = defaultdict(lambda: {'count': 0, 'total_size_bytes': 0})
    
    print(f"Traversing bare-metal filesystem with {args.workers} process workers...")
    
    tasks = []
    for root, dirs, files in os.walk(root_path, topdown=True):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(root, d))]
        
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if not os.path.islink(file_path):
                tasks.append((file_path, file_name, args.no_hash, args.max_hash_size, args.entropy))

    # Use multiprocessing instead of multithreading for CPU bound ops (like Hashing/Entropy)
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as executor:
        for file_data, error in executor.map(process_file_worker, tasks, chunksize=100):
            if file_data:
                files_manifest.append(file_data)
                
                # Global counts
                metadata['total_files'] += 1
                metadata['total_size'] += file_data['size']
                
                # Filetype specific counts
                lang = file_data['lang']
                type_stats[lang]['count'] += 1
                type_stats[lang]['total_size_bytes'] += file_data['size']
                
            if error:
                errors.append(error)

    # Calculate directory sizes
    metadata['directory_sizes'] = compute_directory_sizes(files_manifest)

    metadata['end_time'] = datetime.now(timezone.utc).isoformat()
    metadata['file_type_statistics'] = dict(type_stats)
    
    return metadata, files_manifest, errors

def export_parquet(metadata, files_manifest, base_name):
    if not PARQUET_AVAILABLE:
        print("Warning: pyarrow not installed. Skipping Parquet emission. (pip install pyarrow)")
        return
        
    print("Writing immutable Parquet evidence lake...")

    # Parquet schema enforcement
    schema = pa.schema([
        ('id', pa.string()),
        ('path', pa.string()),
        ('filename', pa.string()),
        ('size', pa.int64()),
        ('created', pa.string()),
        ('modified', pa.string()),
        ('permissions', pa.string()),
        ('uid', pa.int64()),
        ('gid', pa.int64()),
        ('inode', pa.int64()),
        ('device', pa.int64()),
        ('mime', pa.string()),
        ('lang', pa.string()),
        ('sha256', pa.string()),
        ('entropy', pa.float64())
    ])

    table = pa.Table.from_pylist(files_manifest, schema=schema)
    
    custom_metadata = table.schema.metadata or {}
    custom_metadata[b'scan_metadata'] = json.dumps(metadata).encode('utf-8')
    table = table.replace_schema_metadata(custom_metadata)
    
    pq_file = f"{base_name}.parquet"
    pq.write_table(table, pq_file, compression='snappy')
    print(f"Parquet artifact created: {pq_file}")

def get_optimal_workers():
    # ARM64-aware tuning or general auto scaling
    try:
        cpus = multiprocessing.cpu_count()
        if platform.machine().lower() in ['arm64', 'aarch64']:
            return max(1, cpus - 1)
        return max(1, cpus - 1)
    except NotImplementedError:
        return 4

def main():
    parser = argparse.ArgumentParser(description="Multi-Diff Engine Forensic Scanner")
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument("volume_name", help="Logical name of the volume")
    parser.add_argument("--workers", type=int, default=get_optimal_workers(), help="Number of IO process workers")
    parser.add_argument("--no-hash", action="store_true", help="Disable SHA256 hashing")
    parser.add_argument("--max-hash-size", type=int, default=1073741824, help="Max file size to hash in bytes (default 1GB)")
    parser.add_argument("--entropy", action="store_true", help="Enable Shannon entropy scoring (first 1MB)")
    parser.add_argument("--parquet", action="store_true", help="Emit a .parquet file instead of/alongside JSON")
    parser.add_argument("--pretty", action="store_true", help="Output pretty formatted JSON")
    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"Error: Target path {args.target} does not exist.")
        sys.exit(1)

    date_str = datetime.now().strftime("%Y_%m_%d")
    base_name = f"{date_str}_{args.volume_name}"
    
    metadata, files_manifest, errors = scan_volume(args.target, args)
    
    files_manifest.sort(key=lambda x: x['path'])
    
    report = {
        "metadata": metadata,
        "files": files_manifest,
        "errors": errors
    }

    if args.parquet:
        export_parquet(metadata, files_manifest, base_name)

    json_file = f"{base_name}.json"
    zip_file = f"{base_name}.zip"
    
    print("Writing UTF-8 safe structured JSON...")
    with open(json_file, 'w', encoding='utf-8') as f:
        if args.pretty:
            json.dump(report, f, ensure_ascii=False, indent=2)
        else:
            json.dump(report, f, ensure_ascii=False, separators=(',', ':'))
        
    print("Compressing JSON payload...")
    with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.write(json_file)
        
    os.remove(json_file)
    print(f"\\nExecution Complete.")
    print(f"Total Files Indexed: {metadata['total_files']}")
    print(f"Errors encountered: {len(errors)}")
    print(f"Upload-ready artifact: {zip_file}")

if __name__ == "__main__":
    main()
`
