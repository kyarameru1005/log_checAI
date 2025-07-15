import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import apache_log_parser
from pprint import pprint # データを綺麗に表示するために追加

# 監視するディレクトリを指定
WATCH_DIR = "/var/log/apache2"

# Apacheの一般的なCombined Log Formatを指定
# あなたの環境に合わせて変更してください
LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
parser = apache_log_parser.make_parser(LOG_FORMAT)

class ChangeHandler(FileSystemEventHandler):
    """ファイル変更を検知し、追記された行をパースするハンドラ"""
    def __init__(self):
        self.last_positions = {}

    def on_modified(self, event):
        if event.is_directory:
            return

        filepath = event.src_path
        last_pos = self.last_positions.get(filepath, 0)

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                f.seek(last_pos)
                new_lines = f.readlines()
                self.last_positions[filepath] = f.tell()

            if new_lines:
                print("\n--- ▽ 新規ログ検知＆パース ▽ ---")
                for line in new_lines:
                    if not line.strip():
                        continue
                    try:
                        # ログ文字列をパースして辞書に変換
                        log_data = parser(line)
                        pprint(log_data) # pprintで辞書を綺麗に表示
                    except ValueError:
                        print(f"  [パース失敗]: {line.strip()}")
                print("--- △ 処理完了 △ ---")

        except Exception as e:
            print(f"エラー: ファイルを読み込めませんでした - {e}")


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
    