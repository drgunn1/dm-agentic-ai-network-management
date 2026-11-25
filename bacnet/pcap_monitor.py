"""
Copyright 2026 NXP
SPDX-License-Identifier: BSD-3-Clause

PCAP File Monitor for BACnet Network Analysis
Watches a directory of PCAP files and analyzes each one when it is new or has
changed since it was last analyzed.
"""


import asyncio
from pathlib import Path
from typing import List
from datetime import datetime

from .anomaly_storage import AnomalyStorage
from .bacnet_parser import BACnetParser
from .anomaly_event import AnomalyEvent

class PCAPMonitor:
    """
    Monitors a directory of PCAP files. A file is analyzed when it first
    appears and again only after its size or modification time changes;
    parse records are kept in the database, so they survive restarts.
    """
    
    def __init__(self, pcap_directory: str, poll_interval: int = 60,
                 anomaly_interval: float = 0):
        """
        Initialize the PCAP monitor.

        Args:
            pcap_directory: Directory containing PCAP files
            poll_interval: Seconds between checks for new or changed files (default: 60)
            anomaly_interval: Seconds to pause after reporting each anomaly, to
                drip-feed them to the dashboard (default: 0, report all at once)
        """
        self.pcap_directory = Path(pcap_directory)
        self.poll_interval = poll_interval
        self.anomaly_interval = anomaly_interval
        self.storage = AnomalyStorage()
        self.parser = BACnetParser()
        self.running = False
        self.anomaly_event = AnomalyEvent()
        
        # Ensure directory exists
        self.pcap_directory.mkdir(parents=True, exist_ok=True)
        
        print(f"[*] PCAP Monitor initialized")
        print(f"[*] Directory: {self.pcap_directory}")
        print(f"[*] Processing interval: {self.poll_interval} seconds")
    
    def get_pcap_files(self) -> List[Path]:
        """Get all PCAP files in the directory."""
        pcap_extensions = ['.pcap', '.cap', '.pcapng']
        files = []
        
        for ext in pcap_extensions:
            files.extend(self.pcap_directory.glob(f'*{ext}'))
        
        return sorted(files)

    @staticmethod
    def _fingerprint(file_path: Path):
        """(size, mtime_ns) of a capture, or None if it can't be read."""
        try:
            st = file_path.stat()
        except OSError:
            return None
        return st.st_size, st.st_mtime_ns

    def get_changed_files(self, pcap_files: List[Path]) -> List[tuple]:
        """
        Return [(path, fingerprint)] for the captures that are new or have
        changed (size or modification time) since they were last analyzed.
        Parse records of captures that no longer exist are dropped.
        """
        parsed = self.storage.get_parsed_files()
        keys = [str(p.resolve()) for p in pcap_files]
        self.storage.forget_parsed_files(keep=keys)
        changed = []
        for path, key in zip(pcap_files, keys):
            fp = self._fingerprint(path)
            if fp is not None and parsed.get(key) != fp:
                changed.append((path, fp))
        return changed

    async def process_file(self, file_path: Path):
        """Process a single PCAP file."""
        try:
            print(f"\n[*] Processing: {file_path.name}")
            print(f"[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Parse the PCAP file
            # Parse in a thread so the web server's event loop stays responsive;
            # the parser spreads packet decoding over the CPU cores itself.
            results = await asyncio.to_thread(self.parser.analyze_pcap, str(file_path))
            
            if not results:
                print(f"[!] No BACnet data found in {file_path.name}")
                return
            
            # Store devices
            for device in results.get('devices', []):
                self.storage.store_device(device)
            
            # Store and notify anomalies
            anomalies = results.get('anomalies', [])
            
            if anomalies:
                print(f"[!] Found {len(anomalies)} anomalies")
                
                for anomaly in anomalies:
                    # Don't include source_file in the anomaly data
                    anomaly_data = {
                        'anomaly_type': anomaly['type'],
                        'severity': anomaly['severity'],
                        'description': anomaly['description'],
                        'details': anomaly.get('details', {}),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Store in database
                    self.storage.store_anomaly(anomaly_data)
                    
                    # Notify via event system
                    await self.anomaly_event.notify(anomaly_data)
                    
                    print(f"  - {anomaly['type']}: {anomaly['description']}")

                    if self.anomaly_interval > 0:
                        await asyncio.sleep(self.anomaly_interval)
            else:
                print(f"[✓] No anomalies detected")
            
            # Store statistics
            stats = results.get('statistics', {})
            if stats:
                print(f"[*] Devices: {stats.get('total_devices', 0)}, "
                      f"Packets: {stats.get('total_packets', 0)}")
        
        except Exception as e:
            print(f"[!] Error processing {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
    
    async def start(self):
        """Start continuous monitoring loop."""
        self.running = True
        print("\n" + "=" * 70)
        print("BACnet PCAP Monitor - Continuous Processing Mode")
        print("=" * 70)
        print(f"Monitoring directory: {self.pcap_directory}")
        print(f"Processing interval: {self.poll_interval} seconds")
        print("Press Ctrl+C to stop")
        print("=" * 70 + "\n")
        
        cycle_count = 0
        
        while self.running:
            try:
                # Get all PCAP files
                pcap_files = self.get_pcap_files()
                
                if not pcap_files:
                    print(f"[!] No PCAP files found in {self.pcap_directory}")
                    print(f"[*] Waiting {self.poll_interval} seconds before retry...")
                    await asyncio.sleep(self.poll_interval)
                    continue
                
                # Only analyze captures that are new or changed since their last parse
                changed = self.get_changed_files(pcap_files)
                if not changed:
                    await asyncio.sleep(self.poll_interval)
                    continue

                cycle_count += 1
                print(f"\n{'=' * 70}")
                print(f"Processing Cycle #{cycle_count}")
                print(f"Files to process: {len(changed)} new or changed "
                      f"({len(pcap_files) - len(changed)} unchanged, skipped)")
                print(f"{'=' * 70}")

                # Process each file
                for file_path, (size, mtime_ns) in changed:
                    if not self.running:
                        break

                    await self.process_file(file_path)
                    # Record the state the file had before parsing, so a capture
                    # still being written during the parse is analyzed again
                    self.storage.mark_file_parsed(str(file_path.resolve()), size, mtime_ns)

                # After processing all files, wait before starting next cycle
                if self.running:
                    print(f"\n[*] Cycle #{cycle_count} complete")
                    print(f"[*] Checking for new or changed files every {self.poll_interval} seconds...")
                    await asyncio.sleep(self.poll_interval)
            
            except asyncio.CancelledError:
                print("\n[*] Monitor stopped")
                break
            except Exception as e:
                print(f"\n[!] Error in monitoring loop: {e}")
                import traceback
                traceback.print_exc()
                await asyncio.sleep(self.poll_interval)
    
    def stop(self):
        """Stop the monitoring loop."""
        print("\n[*] Stopping PCAP monitor...")
        self.running = False
        self.parser.close()

