import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# 監視するディレクトリを指定
WATCH_DIR = "./logs" # ← ここを監視したいディレクトリのパスに変更してください

# ログファイルが変更されたときに実行される処理を定義
class ChangeHandler(FileSystemEventHandler):
    """ファイル変更を検知するハンドラ"""

    def on_modified(self, event):
        # ファイルが変更された場合
        if not event.is_directory:
            print(f"検知: ファイルが変更されました -> {event.src_path}")
            # ここに、変更されたファイルの内容を読み込んで分析する処理を追加していく

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    
    print(f"--- ログ監視を開始します ---")
    print(f"監視対象ディレクトリ: {WATCH_DIR}")

    # 監視を開始
    event_handler = ChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True) # recursive=Trueでサブディレクトリも監視
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("--- 監視を終了します ---")
    observer.join()
    