#!/usr/bin/env python3
"""
FIMonacci Client
Standalone client for scanning local file system and uploading to FIMonacci server.
No registration required - uses unique client ID.
"""

import os
import sys
import hashlib
import json
import socket
import argparse
import secrets
import time
import signal
from pathlib import Path
from typing import List, Dict, Optional, Set
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


class FIMFileEventHandler(FileSystemEventHandler):
    """Watchdog event handler for file system events"""
    
    def __init__(self, client, hash_cache: Dict[str, str]):
        """
        Initialize event handler
        
        Args:
            client: FIMonacciClient instance
            hash_cache: Dictionary of path -> hash for tracking file states
        """
        super().__init__()
        self.client = client
        self.hash_cache = hash_cache
        self.known_files: Set[str] = set(hash_cache.keys())
    
    def on_created(self, event):
        """Handle file creation events"""
        if event.is_directory:
            return
        self._handle_file_event(event.src_path, "created")
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
        self._handle_file_event(event.src_path, "modified")
    
    def on_deleted(self, event):
        """Handle file deletion events"""
        if event.is_directory:
            return
        self._handle_file_event(event.src_path, "deleted")
    
    def on_moved(self, event):
        """Handle file move/rename events"""
        if event.is_directory:
            return
        # Treat move as delete + create
        if event.src_path in self.known_files:
            self._handle_file_event(event.src_path, "deleted")
        if hasattr(event, 'dest_path') and event.dest_path:
            self._handle_file_event(event.dest_path, "created")
    
    def _handle_file_event(self, filepath: str, event_type: str):
        """Process file system event and send to server"""
        try:
            # For deleted files, we need to get the path before resolving
            # because the file no longer exists
            if event_type == "deleted":
                # Try to get absolute path, but file might not exist
                try:
                    abs_path = str(Path(filepath).resolve())
                except (OSError, ValueError):
                    # File doesn't exist, use path as-is
                    abs_path = str(filepath)
                
                # Get old hash from cache before removing
                old_hash = self.hash_cache.get(abs_path, "unknown")
                
                # Send alert to server
                self.client._send_event_alert(abs_path, old_hash, None, "deleted")
                
                # Remove from cache
                if abs_path in self.hash_cache:
                    del self.hash_cache[abs_path]
                if abs_path in self.known_files:
                    self.known_files.remove(abs_path)
                
                return
            
            # For other events, file should exist
            abs_path = str(Path(filepath).resolve())
            
            if event_type == "created":
                # File was created - calculate hash and send
                file_hash = self.client.calculate_md5(abs_path)
                if file_hash:
                    self.client._send_event_alert(abs_path, None, file_hash, "created")
                    # Update cache
                    self.hash_cache[abs_path] = file_hash
                    self.known_files.add(abs_path)
                    # Also upload hash to server with event_type
                    file_size = Path(abs_path).stat().st_size if Path(abs_path).exists() else 0
                    self.client.upload_files([{
                        'path': abs_path,
                        'hash_md5': file_hash,
                        'file_size': file_size,
                        'event_type': 'created'
                    }])
            
            elif event_type == "modified":
                # File was modified - calculate new hash and compare
                new_hash = self.client.calculate_md5(abs_path)
                if new_hash:
                    old_hash = self.hash_cache.get(abs_path)
                    if old_hash and old_hash != new_hash:
                        # Hash changed - send alert
                        self.client._send_event_alert(abs_path, old_hash, new_hash, "hash_mismatch")
                        # Update cache
                        self.hash_cache[abs_path] = new_hash
                        # Upload new hash with event_type
                        file_size = Path(abs_path).stat().st_size if Path(abs_path).exists() else 0
                        self.client.upload_files([{
                            'path': abs_path,
                            'hash_md5': new_hash,
                            'file_size': file_size,
                            'event_type': 'hash_mismatch'
                        }])
                    elif not old_hash:
                        # File not in cache - treat as created
                        self.client._send_event_alert(abs_path, None, new_hash, "created")
                        self.hash_cache[abs_path] = new_hash
                        self.known_files.add(abs_path)
        
        except Exception as e:
            print(f"⚠️  Error handling event {event_type} for {filepath}: {e}")


class FIMonacciClient:
    """Standalone client for FIMonacci server"""
    
    def __init__(self, server_url: str, config_path: str = "client_config.json"):
        """
        Initialize the client
        
        Args:
            server_url: Base URL of the FIMonacci server (e.g., http://localhost:5000)
            config_path: Path to config file for storing client ID
        """
        self.server_url = server_url.rstrip('/')
        self.config_path = Path(config_path)
        self.session = requests.Session()
        
        # Load or create client ID
        self.client_id, self.hostname = self._load_or_create_client_id()
        
        # Set headers
        self.session.headers.update({
            'Content-Type': 'application/json',
            'X-Client-ID': self.client_id,
            'X-Hostname': self.hostname
        })
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Register/update client on server
        self._register_client()
    
    def _get_hostname(self) -> str:
        """Get system hostname"""
        try:
            return socket.gethostname()
        except:
            return "unknown"
    
    def _load_or_create_client_id(self) -> tuple:
        """Load existing client ID or create a new one"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    client_id = config.get('client_id')
                    hostname = config.get('hostname', self._get_hostname())
                    if client_id:
                        return client_id, hostname
            except Exception as e:
                print(f"⚠️  Warning: Could not load config: {e}")
        
        # Create new client ID
        client_id = secrets.token_urlsafe(32)  # 43 characters
        hostname = self._get_hostname()
        
        # Save to config
        try:
            config = {
                'client_id': client_id,
                'hostname': hostname,
                'created_at': datetime.utcnow().isoformat()
            }
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"✅ Created new client ID: {client_id[:16]}...")
        except Exception as e:
            print(f"⚠️  Warning: Could not save config: {e}")
        
        return client_id, hostname
    
    def _register_client(self):
        """Register or update client on server"""
        try:
            response = self.session.post(
                f"{self.server_url}/api/client/register",
                json={
                    "client_id": self.client_id,
                    "hostname": self.hostname
                },
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                print(f"✅ Client registered: {self.hostname} ({self.client_id[:16]}...)")
            else:
                print(f"⚠️  Warning: Server response {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"⚠️  Warning: Could not register client: {e}")
    
    def calculate_md5(self, filepath: str) -> Optional[str]:
        """
        Calculate MD5 hash of a file
        
        Args:
            filepath: Path to the file
            
        Returns:
            MD5 hash as hex string, or None if error
        """
        try:
            path_obj = Path(filepath)
            if not path_obj.exists() or not path_obj.is_file():
                return None
            
            hash_md5 = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except (PermissionError, IOError, OSError) as e:
            print(f"⚠️  Warning: Could not read {filepath}: {e}")
            return None
        except Exception as e:
            print(f"⚠️  Warning: Error calculating hash for {filepath}: {e}")
            return None
    
    def scan_folder(self, folder_path: str) -> List[Dict]:
        """
        Scan a folder and calculate hashes for all files
        
        Args:
            folder_path: Path to folder to scan
            
        Returns:
            List of dictionaries with file information
        """
        folder = Path(folder_path)
        if not folder.exists() or not folder.is_dir():
            print(f"❌ Error: Folder not found: {folder_path}")
            return []
        
        print(f"📁 Scanning folder: {folder_path}")
        
        files_data = []
        processed_count = 0
        
        try:
            for file_path in folder.rglob("*"):
                if not file_path.is_file():
                    continue
                
                try:
                    abs_path = str(file_path.resolve())
                    file_size = file_path.stat().st_size
                    
                    print(f"  📄 Processing: {file_path.name} ({file_size:,} bytes)", end='\r')
                    
                    file_hash = self.calculate_md5(abs_path)
                    if file_hash:
                        files_data.append({
                            'path': abs_path,
                            'hash_md5': file_hash,
                            'file_size': file_size
                        })
                        processed_count += 1
                except Exception as e:
                    print(f"\n⚠️  Warning: Error processing {file_path}: {e}")
                    continue
            
            print(f"\n✅ Scanned {processed_count} files")
            return files_data
            
        except Exception as e:
            print(f"\n❌ Error scanning folder: {e}")
            return []
    
    def upload_files(self, files_data: List[Dict], batch_size: int = 100) -> Dict:
        """
        Upload file hashes to the server
        
        Args:
            files_data: List of file information dictionaries
            batch_size: Number of files to upload per batch
            
        Returns:
            Response dictionary with results
        """
        if not files_data:
            return {"processed": 0, "errors": [], "success": []}
        
        print(f"\n📤 Uploading {len(files_data)} file hashes to server...")
        
        upload_url = f"{self.server_url}/api/upload/hashes"
        
        results = {
            "processed": 0,
            "errors": [],
            "success": []
        }
        
        # Upload in batches
        total_batches = (len(files_data) + batch_size - 1) // batch_size
        
        for i in range(0, len(files_data), batch_size):
            batch = files_data[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            
            print(f"  📦 Uploading batch {batch_num}/{total_batches} ({len(batch)} files)...", end='\r')
            
            try:
                response = self.session.post(
                    upload_url,
                    json={"files": batch},
                    timeout=300  # 5 minute timeout for large batches
                )
                
                if response.status_code == 200:
                    result = response.json()
                    results["processed"] += result.get("processed", 0)
                    results["errors"].extend(result.get("errors", []))
                    results["success"].extend(result.get("success", []))
                else:
                    error_msg = f"Batch {batch_num}: Server error {response.status_code}"
                    results["errors"].append(error_msg)
                    print(f"\n  ❌ Error uploading batch {batch_num}: {response.status_code}")
                    if response.text:
                        try:
                            error_data = response.json()
                            print(f"     Error: {error_data.get('error', response.text[:200])}")
                        except:
                            print(f"     Response: {response.text[:200]}")
            except requests.exceptions.Timeout:
                error_msg = f"Batch {batch_num}: Upload timeout"
                results["errors"].append(error_msg)
                print(f"\n  ⏱️  Timeout uploading batch {batch_num}")
            except Exception as e:
                error_msg = f"Batch {batch_num}: {str(e)}"
                results["errors"].append(error_msg)
                print(f"\n  ❌ Error uploading batch {batch_num}: {e}")
        
        print(f"\n✅ Upload complete!")
        print(f"   Processed: {results['processed']} files")
        print(f"   Errors: {len(results['errors'])}")
        print(f"   Success: {len(results['success'])}")
        
        if results["errors"]:
            print(f"\n⚠️  First 5 errors:")
            for error in results["errors"][:5]:
                print(f"   - {error}")
        
        return results
    
    def _send_event_alert(self, filepath: str, old_hash: Optional[str], new_hash: Optional[str], event_type: str):
        """
        Send file event alert directly to server
        
        Args:
            filepath: Path to the file
            old_hash: Previous hash (None for created files)
            new_hash: Current hash (None for deleted files)
            event_type: Type of event (created, modified, deleted, hash_mismatch)
        """
        try:
            # For deleted files, we can't resolve the path (file doesn't exist)
            # So we use the path as-is or try to normalize it
            try:
                abs_path = str(Path(filepath).resolve()).replace('\\', '/')
            except (OSError, ValueError):
                # File doesn't exist (deleted), use path as-is
                abs_path = str(filepath).replace('\\', '/')
            
            alert_data = {
                "path": abs_path,
                "initial_hash": old_hash or "unknown",
                "current_hash": new_hash,
                "alert_type": event_type
            }
            
            # Send alert to server via dedicated endpoint
            try:
                response = self.session.post(
                    f"{self.server_url}/api/upload/event",
                    json=alert_data,
                    timeout=10
                )
                
                if response.status_code == 200:
                    try:
                        file_name = Path(filepath).name if Path(filepath).exists() else (Path(abs_path).name if abs_path else "unknown")
                    except:
                        file_name = abs_path.split('/')[-1] if abs_path else "unknown"
                    print(f"  📢 Event: {event_type.upper()} - {file_name}")
                elif response.status_code == 404:
                    # Endpoint not found - might need server restart
                    print(f"  ⚠️  Failed to send {event_type} event: Endpoint not found (404)")
                    print(f"     Make sure server is running and has been restarted after update")
                    print(f"     URL: {self.server_url}/api/upload/event")
                else:
                    error_msg = response.text[:200] if response.text else f"Status {response.status_code}"
                    print(f"  ⚠️  Failed to send {event_type} event: {response.status_code} - {error_msg}")
            except requests.exceptions.RequestException as e:
                print(f"  ⚠️  Error sending {event_type} event to server: {e}")
                print(f"     URL: {self.server_url}/api/upload/event")
        
        except Exception as e:
            print(f"⚠️  Error sending alert: {e}")
    
    def _load_hash_cache(self) -> Dict[str, str]:
        """Load local hash cache from file"""
        cache_file = self.config_path.parent / "hash_cache.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_hash_cache(self, cache: Dict[str, str]):
        """Save local hash cache to file"""
        cache_file = self.config_path.parent / "hash_cache.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(cache, f, indent=2)
        except Exception as e:
            print(f"⚠️  Warning: Could not save hash cache: {e}")
    
    def scan_folder_changes(self, folder_path: str, last_hashes: Dict[str, str]) -> tuple:
        """
        Scan folder and return only changed/new files
        
        Args:
            folder_path: Path to folder to scan
            last_hashes: Dictionary of path -> hash from last scan
            
        Returns:
            Tuple of (changed_files_list, current_hashes_dict)
        """
        folder = Path(folder_path)
        if not folder.exists() or not folder.is_dir():
            return [], {}
        
        changed_files = []
        current_hashes = {}
        
        try:
            for file_path in folder.rglob("*"):
                if not file_path.is_file():
                    continue
                
                try:
                    abs_path = str(file_path.resolve())
                    file_size = file_path.stat().st_size
                    
                    # Calculate current hash
                    file_hash = self.calculate_md5(abs_path)
                    if not file_hash:
                        continue
                    
                    current_hashes[abs_path] = file_hash
                    
                    # Check if file is new or changed
                    last_hash = last_hashes.get(abs_path)
                    if last_hash != file_hash:
                        changed_files.append({
                            'path': abs_path,
                            'hash_md5': file_hash,
                            'file_size': file_size
                        })
                except Exception:
                    continue
            
            return changed_files, current_hashes
            
        except Exception as e:
            print(f"⚠️  Error scanning folder: {e}")
            return [], {}
    
    def run(self, folders: List[str], continuous: bool = False, interval: int = 60):
        """
        Main method to scan and upload files from specified folders
        
        Args:
            folders: List of folder paths to scan
            continuous: If True, run continuously and monitor for changes
            interval: Seconds between scans when running continuously
        """
        print("🚀 FIMonacci Client Starting...\n")
        print(f"🆔 Client ID: {self.client_id[:16]}...")
        print(f"💻 Hostname: {self.hostname}\n")
        
        if not folders:
            print("❌ Error: No folders specified to scan")
            return
        
        print(f"📂 Monitoring folder(s):")
        for folder in folders:
            print(f"   - {folder}")
        print()
        
        # Load hash cache
        hash_cache = self._load_hash_cache()
        
        # Initial scan and upload
        print("🔍 Performing initial scan...")
        all_files_data = []
        all_current_hashes = {}
        
        for folder in folders:
            files_data = self.scan_folder(folder)
            all_files_data.extend(files_data)
            # Build hash cache from initial scan
            for file_data in files_data:
                all_current_hashes[file_data['path']] = file_data['hash_md5']
        
        if all_files_data:
            print("\n📤 Uploading initial file hashes...")
            self.upload_files(all_files_data)
            hash_cache.update(all_current_hashes)
            self._save_hash_cache(hash_cache)
        else:
            print("⚠️  No files found to upload")
        
        if not continuous:
            print("\n✅ Initial scan complete. Use --continuous flag to monitor for changes.")
            return
        
        # Continuous monitoring with watchdog
        print(f"\n🔄 Starting real-time monitoring with watchdog...")
        print("   Press Ctrl+C to stop\n")
        
        # Create event handler
        event_handler = FIMFileEventHandler(self, hash_cache)
        observer = Observer()
        
        # Schedule watching for each folder
        for folder in folders:
            folder_path = Path(folder)
            if folder_path.exists() and folder_path.is_dir():
                observer.schedule(event_handler, str(folder_path), recursive=True)
                print(f"   👁️  Watching: {folder}")
        
        # Start observer
        observer.start()
        print("   ✅ Watchdog started - monitoring file system events in real-time\n")
        
        running = True
        
        def signal_handler(sig, frame):
            nonlocal running
            print("\n\n⚠️  Stopping monitor...")
            running = False
            observer.stop()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            # Keep running and periodically save cache
            while running:
                time.sleep(10)  # Save cache every 10 seconds
                self._save_hash_cache(hash_cache)
        except KeyboardInterrupt:
            pass
        finally:
            observer.stop()
            observer.join()
            self._save_hash_cache(hash_cache)
        
        print("\n✅ Monitoring stopped")




def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="FIMonacci Client - Scan local files and upload to server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan specific folder
  python client.py -u http://localhost:5000 -p /path/to/folder
  
  # Scan multiple folders
  python client.py -u http://localhost:5000 -p /home/user/docs -p /home/user/pics
  
  # Remote server
  python client.py -u https://your-server.com -p /var/www/html

Note: 
  - Client ID and hostname are automatically generated and saved
  - No registration or token required - everything is automatic!
        """
    )
    
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='FIMonacci server URL (e.g., http://localhost:5000)'
    )
    
    parser.add_argument(
        '-p', '--path',
        action='append',
        required=True,
        help='Folder path to scan (can be used multiple times for multiple folders)'
    )
    
    parser.add_argument(
        '-c', '--continuous',
        action='store_true',
        help='Run continuously and monitor for file changes'
    )
    
    parser.add_argument(
        '-i', '--interval',
        type=int,
        default=60,
        help='Interval in seconds between scans when running continuously (default: 60)'
    )
    
    args = parser.parse_args()
    
    # Validate server URL
    if not args.url:
        print("❌ Error: Server URL is required. Use -u or --url")
        parser.print_help()
        sys.exit(1)
    
    # Validate paths
    if not args.path:
        print("❌ Error: At least one folder path is required. Use -p or --path")
        parser.print_help()
        sys.exit(1)
    
    # Validate folders exist
    for folder_path in args.path:
        folder = Path(folder_path)
        if not folder.exists():
            print(f"❌ Error: Folder does not exist: {folder_path}")
            sys.exit(1)
        if not folder.is_dir():
            print(f"❌ Error: Not a directory: {folder_path}")
            sys.exit(1)
    
    # Create client and run (automatically creates client ID and registers)
    try:
        print(f"🚀 Connecting to server: {args.url}")
        client = FIMonacciClient(server_url=args.url)
        print(f"✅ Connected successfully!\n")
    except Exception as e:
        print(f"❌ Error connecting to server: {e}")
        print(f"   Make sure the server is running at {args.url}")
        sys.exit(1)
    
    # Run scan and upload
    try:
        client.run(args.path, continuous=args.continuous, interval=args.interval)
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

