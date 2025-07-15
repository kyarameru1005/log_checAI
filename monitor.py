import time
import joblib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import apache_log_parser
from pprint import pprint

# --- Configuration ---
WATCH_DIR = "/var/log/apache2"
LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
parser = apache_log_parser.make_parser(LOG_FORMAT)

# --- 1. ルールベースのチェックを追加 ---
# このリストに含まれる文字列がリクエストに含まれていたら、即座に異常と判断
BLACKLISTED_PATTERNS = [
    "/.env",
    "/.git",
    "/wp-config.php",
    "etc/passwd",
    "SELECT",
    "UNION",
    "INSERT",
    "<script>",
]

def is_anomaly_by_rule(request_line):
    """ルールに合致するかをチェックする"""
    for pattern in BLACKLISTED_PATTERNS:
        # 大文字・小文字を区別せずにチェック
        if pattern.lower() in request_line.lower():
            return True
    return False

# --- 2. 訓練済みAIモデルと変換器の読み込み ---
try:
    print("--- 訓練済みAIモデルを読み込んでいます... ---")
    model = joblib.load('log_anomaly_model.joblib')
    vectorizer = joblib.load('tfidf_vectorizer.joblib')
    print("   ✅ AIモデルの準備完了。")
except FileNotFoundError:
    print("[エラー] AIモデルファイルが見つかりません。")
    print("train_model.py を実行して、モデルを訓練してください。")
    exit()

# --- 3. AIによるリアルタイム予測関数 ---
def predict_log_anomaly(log_text):
    """AIが異常かどうかを予測する"""
    vectorized_text = vectorizer.transform([log_text])
    prediction = model.predict(vectorized_text)[0]
    return bool(prediction)

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
                if not line.strip():
                    continue
                try:
                    log_data = parser(line)
                    request_line = log_data.get('request_first_line', '')

                    # --- ★★★ ハイブリッド判定 ★★★ ---
                    # ステップ1: まずルールでチェック
                    if is_anomaly_by_rule(request_line):
                        print("\n🚨🚨🚨【ルールで異常を検知】🚨🚨🚨")
                        pprint(log_data)
                    # ステップ2: ルールに該当しない場合のみ、AIでチェック
                    elif predict_log_anomaly(request_line):
                        print("\n🚨🚨🚨【AIが異常を検知】🚨🚨🚨")
                        pprint(log_data)
                    else:
                        print(f"\n✅ [判断: 正常] - {request_line}")

                except ValueError:
                    pass
        except Exception as e:
            print(f"エラーが発生しました: {e}")

if __name__ == "__main__":
    print("\n--- TwinAI - Log Sentinel (ハイブリッド版) 起動 ---")
    print("--- リアルタイムログ監視を開始します (Ctrl+Cで終了) ---")
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