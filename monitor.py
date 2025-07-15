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

# --- Isolation Action ---
def trigger_isolation(log_data):
    """
    異常検知をトリガーに、Apacheコンテナを起動する。
    """
    print("\n--- 🚀 隔離シーケンス開始 ---")
    print("異常なリクエストを検知。Apacheサンドボックス環境を起動します。")
    
    try:
        # 'httpd'コンテナをバックグラウンドで起動し、停止時に自動で削除する
        # コマンド: docker run -d --rm httpd:latest
        # -d: デタッチモード（バックグラウンド実行）
        # --rm: コンテナ停止時に自動で削除
        command = ["docker", "run", "-d", "--rm", "httpd:latest"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        container_id = result.stdout.strip()
        print(f"\n✅ サンドボックス起動成功！")
        print(f"   コンテナID: {container_id[:12]}") # IDを短縮して表示
        print("   (確認コマンド: 'docker ps')")
        
    except FileNotFoundError:
        print("\n[エラー] 'docker' コマンドが見つかりません。")
    except subprocess.CalledProcessError as e:
        print("\n[エラー] Dockerコンテナの起動に失敗しました。")
        print(f"詳細: {e.stderr}")

# --- Change Handler Class (変更なし) ---
class ChangeHandler(FileSystemEventHandler):
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
                        trigger_isolation(log_data)
                except ValueError:
                    pass
        except Exception:
            pass

# --- Main Execution (変更なし) ---
if __name__ == "__main__":
    print(f"--- ログ監視を開始します (Ctrl+Cで終了) ---")
    print(f"監視対象ディレクトリ: {WATCH_DIR}")
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