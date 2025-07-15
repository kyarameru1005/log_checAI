import time
import subprocess
import json
from datetime import datetime # 日時を扱うためにインポート
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import apache_log_parser
from pprint import pprint

# --- Configuration ---
WATCH_DIR = "/var/log/apache2"
LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
parser = apache_log_parser.make_parser(LOG_FORMAT)
ANALYSIS_FILE = "analysis_results.jsonl"

# --- Anomaly Detection Rule ---
def is_anomaly(log_data):
    try:
        status = int(log_data['status'])
        if status >= 400:
            return True
    except (ValueError, KeyError):
        return False
    return False

# --- Analysis Sequence ---
def trigger_analysis_sequence(log_data):
    print("\n--- 🚀 分析シーケンス開始 ---")
    
    container_id = None
    try:
        print("1. Apacheサンドボックス環境を起動中...")
        command = ["docker", "run", "-d", "--rm", "twinai-apache-sandbox"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        container_id = result.stdout.strip()
        print(f"   ✅ 起動成功 (コンテナID: {container_id[:12]})")
    except Exception as e:
        print(f"[エラー] サンドボックスの起動に失敗しました: {e}")
        return

    reproduce_output = ""
    try:
        print(f"\n2. コンテナ {container_id[:12]} に対して攻撃を再現中...")
        request_path = log_data.get('request_first_line', '').split()[1]
        reproduce_command = ["docker", "exec", container_id, "curl", f"http://localhost:80{request_path}"]
        reproduce_result = subprocess.run(reproduce_command, capture_output=True, text=True, check=False)
        reproduce_output = reproduce_result.stdout if reproduce_result.stdout else reproduce_result.stderr
        print("   ✅ 再現完了。")
    except Exception as e:
        reproduce_output = f"再現エラー: {e}"
        print(f"[エラー] 攻撃の再現に失敗しました: {e}")

    try:
        print(f"\n3. 分析結果を {ANALYSIS_FILE} に記録中...")
        analysis_record = {
            # ↓↓↓ ここを修正！ ↓↓↓
            "timestamp": datetime.now().isoformat(), # .isoformat() を付けて文字列に変換
            "original_log": log_data,
            "reproduction_result": reproduce_output.strip()
        }
        with open(ANALYSIS_FILE, "a") as f:
            f.write(json.dumps(analysis_record) + "\n")
        print("   ✅ 記録完了。")
    except Exception as e:
        print(f"[エラー] 結果の記録に失敗しました: {e}")

    finally:
        if container_id:
            print("\n4. サンドボックス環境を破棄します。")
            subprocess.run(["docker", "stop", container_id], capture_output=True, text=True)

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
                    if is_anomaly(log_data):
                        print("\n🚨🚨🚨 異常検知 🚨🚨🚨"); pprint(log_data)
                        trigger_analysis_sequence(log_data)
                except ValueError: pass
        except Exception: pass

if __name__ == "__main__":
    print(f"--- ログ監視を開始します (Ctrl+Cで終了) ---")
    event_handler = ChangeHandler(); observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True); observer.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        observer.stop(); print("\n--- 監視を終了します ---")
    observer.join()