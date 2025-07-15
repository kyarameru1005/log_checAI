import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# 監視するディレクトリを指定
WATCH_DIR = "/ver/log/apache2/access.log"

class ChangeHandler(FileSystemEventHandler):
    """ファイル変更を検知し、追記された行を読み取るハンドラ"""
    def __init__(self):
        # ファイルごとの最終読み取り位置を保存する辞書
        self.last_positions = {}

    def on_modified(self, event):
        # ディレクトリ自身の変更は無視
        if event.is_directory:
            return

        filepath = event.src_path
        # ファイルの最終読み取り位置を取得。なければ0から。
        last_pos = self.last_positions.get(filepath, 0)

        try:
            # ファイルを開いて、前回読み終わった位置から読み込みを開始
            with open(filepath, 'r', encoding='utf-8') as f:
                f.seek(last_pos)
                new_lines = f.readlines()
                # 今回読み終わった位置を保存
                self.last_positions[filepath] = f.tell()

            # 新しく追記された行があれば表示
            if new_lines:
                print("\n--- ▽ 新規ログ検知 ▽ ---")
                for line in new_lines:
                    print(f"  [内容] {line.strip()}")
                print("--- △ 検知完了 △ ---")

        except Exception as e:
            print(f"エラー: ファイルを読み込めませんでした - {e}")


if __name__ == "__main__":
    print(f"--- ログ監視を開始します (Ctrl+Cで終了) ---")
    print(f"監視対象ディレクトリ: {WATCH_DIR}")

    # 監視を開始
    event_handler = ChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
        print("\n--- 監視を終了します ---")
    observer.join()