"""
services/scheduler.py — Continuous Monitoring Scheduler daemon thread.
Loads active monitoring jobs from Firestore and executes them in subprocesses.
"""

from __future__ import annotations

import os
import sys
import time
import subprocess
import threading
from datetime import datetime, timezone, timedelta
from firebase import db as firebase_db

# Prevent launching multiple threads
_scheduler_started = False
_scheduler_lock = threading.Lock()


def start_scheduler() -> None:
    """Start the background scheduler thread if not already running."""
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        
        # Start background worker thread
        worker = threading.Thread(target=_scheduler_loop, daemon=True, name="SOC-Monitoring-Scheduler")
        worker.start()
        _scheduler_started = True
        print("SOC Monitoring Scheduler daemon thread started successfully.")


def _scheduler_loop() -> None:
    """Daemon thread loop checking for overdue scans every 15 seconds."""
    # Ensure Firebase is initialised
    from firebase import config as firebase_config
    try:
        firebase_config.initialise()
    except Exception as e:
        print(f"Scheduler failed to initialize Firebase: {e}")
        return

    # Track active running subprocesses to prevent duplicate runs
    running_scans: dict[str, subprocess.Popen] = {}

    while True:
        try:
            # 1. Clean up completed subprocesses
            finished_assets = []
            for asset_id, process in running_scans.items():
                if process.poll() is not None:
                    finished_assets.append(asset_id)
            for asset_id in finished_assets:
                running_scans.pop(asset_id)

            # 2. Query Firestore database for active monitored assets
            db_client = firebase_db.get_db()
            now = datetime.now(timezone.utc)
            
            # Query all assets that have monitoring enabled
            assets_ref = db_client.collection(firebase_db.ASSETS).where("monitoring_enabled", "==", True).stream()
            
            for doc in assets_ref:
                asset_data = doc.to_dict()
                asset_id = doc.id
                
                # Check if this asset is already scanning
                if asset_id in running_scans:
                    continue
                
                uid = asset_data.get("uid")
                url = asset_data.get("url")
                next_run = asset_data.get("next_scheduled_scan_at")
                
                # Check if scan is due
                is_due = False
                if next_run is None:
                    is_due = True
                else:
                    # Parse next_run if it is string or datetime
                    if isinstance(next_run, datetime):
                        is_due = next_run <= now
                    else:
                        is_due = True
                
                if is_due:
                    print(f"Asset {url} is due for scheduled scan. Spawning process...")
                    # Spawn standalone scan runner in a subprocess
                    process = subprocess.Popen([
                        sys.executable,
                        os.path.join(os.path.dirname(__file__), "scan_runner.py"),
                        "--url", url,
                        "--uid", uid,
                        "--asset_id", asset_id
                    ])
                    running_scans[asset_id] = process
                    
        except Exception as e:
            print(f"Error in scheduler loop: {e}")
            
        time.sleep(15)
