import time
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import apache_log_parser
from pprint import pprint

# --- Configuration ---
WATCH_DIR = "/var/log/apache2"
LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
parser = apache_log_parser.make_parser(LOG_FORMAT)

# --- Anomaly Detection Rule ---
def is_anomaly(log_data):
    try:
        status = int(log_data['status'])
        if status >= 400:
            return True
    except (ValueError, KeyError):
        return False
    return False

# --- Isolation & Reproduction Action ---
def trigger_reproduce_sequence(log_data):
    """
    異常検知をトリガーに、コンテナを起動し、攻撃を再現する。
    """
    print("\n--- 🚀 再現シーケンス開始 ---")
    
    # 1. サンドボックス環境（Apacheコンテナ）を起動
    container_id = None
    try:
        print("1. Apacheサンドボックス環境を起動中...")
        command = ["docker", "run", "-d", "--rm", "httpd:latest"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        container_id = result.stdout.strip()
        print(f"   ✅ 起動成功 (コンテナID: {container_id[:12]})")
    except Exception as e:
        print(f"[エラー] サンドボックスの起動に失敗しました: {e}")
        return # 起動に失敗したら処理を中断

    # 2. 攻撃リクエストをコンテナ内で再現
    try:
        print(f"\n2. コンテナ {container_id[:12]} に対して攻撃を再現中...")
        # "GET /path/to/resource HTTP/1.1" から "/path/to/resource" を抽出
        request_path = log_data.get('request_first_line', '').split()[1]
        
        # docker exec [container_id] curl http://localhost:80[path]
        reproduce_command = [
            "docker", "exec", container_id,
            "curl", f"http://localhost:80{request_path}"
        ]
        
        reproduce_result = subprocess.run(reproduce_command, capture_output=True, text=True, check=True)
        print("   ✅ 再現完了。コンテナからの応答:")
        print("------------------------------------------")
        print(reproduce_result.stdout)
        print("------------------------------------------")

    except Exception as e:
        print(f"[エラー] 攻撃の再現に失敗しました: {e}")

    # 3. 分析のためにコンテナを一定時間残し、その後停止（ここでは即時停止）
    finally:
        print("\n3. 分析完了。サンドボックス環境を破棄します。")
        subprocess.run(["docker", "stop", container_id], capture_output=True)


class ChangeHandler(FileSystemEventHandler):
    # (このクラスの中身は変更ありません)
    def __init__(self):
        self.last_positions = {}
    def on_modified(self, event):
        if event.is_directory or 'access.log' not in event.src_path:
            return
        filepath = event.src_path
        last_pos = self.last_positions.get(filepath, 0)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                f.seek(last_pos)
                new_lines = f.readlines()
                self.last_positions[filepath] = f.tell()
            for line in new_lines:
                if not line.strip(): continue
                try:
                    log_data = parser(line)
                    if is_anomaly(log_data):
                        print("\n🚨🚨🚨 異常検知 🚨🚨🚨")
                        pprint(log_data)
                        trigger_reproduce_sequence(log_data)
                except ValueError: pass
        except Exception: pass

if __name__ == "__main__":
    # (main処理は変更ありません)
    print(f"--- ログ監視を開始します (Ctrl+Cで終了) ---")
    event_handler = ChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n--- 監視を終了します ---")
    observer.join()