import time
import subprocess
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import apache_log_parser
from pprint import pprint

# --- Configuration ---
WATCH_DIR = "/var/log/apache2"
LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
parser = apache_log_parser.make_parser(LOG_FORMAT)
TRAINING_DATA_FILE = "training_data.jsonl" # ファイル名を変更

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def is_anomaly(log_data):
    try:
        status = int(log_data['status'])
        if status >= 400:
            return True # 異常
    except (ValueError, KeyError):
        return False
    return False # 正常

def record_log_data(log_data, is_anomaly_flag):
    """全てのログを、正常か異常かのラベル付きで記録する"""
    try:
        record = {
            "timestamp": datetime.now().isoformat(),
            "log": log_data,
            "is_anomaly": is_anomaly_flag # 正常(False)か異常(True)かのラベル
        }
        with open(TRAINING_DATA_FILE, "a") as f:
            f.write(json.dumps(record, cls=DateTimeEncoder) + "\n")
        
        if is_anomaly_flag:
            print(f"   記録完了 (異常)")
        else:
            print(f"   記録完了 (正常)")

    except Exception as e:
        print(f"[エラー] データの記録に失敗しました: {e}")

class ChangeHandler(FileSystemEventHandler):
    def __init__(self): self.last_positions = {}
    def on_modified(self, event):
        if event.is_directory or 'access.log' not in event.src_path: return
        filepath = event.src_path
        last_pos = self.last_positions.get(filepath, 0)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                f.seek(last_pos); new_lines = f.readlines(); self.last_positions[filepath] = f.tell()
            for line in new_lines:
                if not line.strip(): continue
                try:
                    log_data = parser(line)
                    anomaly_flag = is_anomaly(log_data)
                    
                    if anomaly_flag:
                        print("\n🚨 異常ログを検知")
                    else:
                        print("\n✅ 正常ログを検知")
                        
                    record_log_data(log_data, anomaly_flag)
                except ValueError: pass
        except Exception: pass

if __name__ == "__main__":
    print(f"--- AI学習用データの収集を開始します (Ctrl+Cで終了) ---")
    event_handler = ChangeHandler(); observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True); observer.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        observer.stop(); print("\n--- データ収集を終了します ---")
    observer.join()