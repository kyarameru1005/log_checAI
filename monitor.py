import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import apache_log_parser
from pprint import pprint

# 監視するディレクトリを指定
WATCH_DIR = "/var/log/apache2"

# Apacheの一般的なCombined Log Format
LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
parser = apache_log_parser.make_parser(LOG_FORMAT)

# --- 異常検知のルールを定義 ---
def is_anomaly(log_data):
    """
    ログデータを受け取り、異常かどうかを判定する関数。
    今回はステータスコードが400以上の場合を「異常」とする。
    """
    try:
        status = int(log_data['status'])
        if status >= 400:
            return True # 異常
    except (ValueError, KeyError):
        # statusが数字でない、またはキーが存在しない場合
        return False
    return False # 正常

class ChangeHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_positions = {}

    def on_modified(self, event):
        if event.is_directory:
            return

        filepath = event.src_path
        # access.log以外のファイルは無視する（error.logなど）
        if 'access.log' not in filepath:
            return

        last_pos = self.last_positions.get(filepath, 0)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                f.seek(last_pos)
                new_lines = f.readlines()
                self.last_positions[filepath] = f.tell()

            for line in new_lines:
                if not line.strip():
                    continue
                try:
                    log_data = parser(line)
                    # 異常検知関数を呼び出す
                    if is_anomaly(log_data):
                        print("\n🚨🚨🚨 異常検知 🚨🚨🚨")
                        pprint(log_data)
                    else:
                        # 正常なログは必要に応じて表示（コメントアウトしてもOK）
                        # print("\n--- [正常] ---")
                        # pprint(log_data)
                        pass
                except ValueError:
                    pass
        except Exception as e:
            # Permission deniedを避けるため、エラー内容は簡潔に
            # print(f"エラー: {e}")
            pass


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