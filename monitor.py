import time
import joblib # AIモデルを読み込むために追加
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import apache_log_parser
from pprint import pprint

# --- Configuration ---
WATCH_DIR = "/var/log/apache2"
LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
parser = apache_log_parser.make_parser(LOG_FORMAT)

# --- 1. 訓練済みAIモデルと変換器の読み込み ---
try:
    print("--- 訓練済みAIモデルを読み込んでいます... ---")
    model = joblib.load('log_anomaly_model.joblib')
    vectorizer = joblib.load('tfidf_vectorizer.joblib')
    print("   ✅ AIモデルの準備完了。")
except FileNotFoundError:
    print("[エラー] AIモデルファイルが見つかりません。")
    print("train_model.py を実行して、モデルを訓練してください。")
    exit()

# --- 2. AIによるリアルタイム予測関数 ---
def predict_log_anomaly(log_text):
    """
    新しいログのテキストを受け取り、AIが異常かどうかを予測する。
    """
    # 学習時と同じように、テキストを数値ベクトルに変換
    vectorized_text = vectorizer.transform([log_text])
    # AIモデルで予測を実行 (結果は [0] や [1] なので、最初の要素を取り出す)
    prediction = model.predict(vectorized_text)[0]
    return bool(prediction) # True (異常) / False (正常) を返す

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
                    request_line = log_data.get('request_first_line', '')

                    # --- AIに予測を依頼 ---
                    is_anomaly = predict_log_anomaly(request_line)

                    if is_anomaly:
                        print("\n🚨🚨🚨【AIが異常を検知】🚨🚨🚨")
                        pprint(log_data)
                        # ここに、以前作成したDockerを起動するなどの
                        # 分析シーケンスを再び組み込むこともできる
                    else:
                        print(f"\n✅ [AIの判断: 正常] - {request_line}")

                except ValueError: pass
        except Exception as e:
            print(f"エラーが発生しました: {e}")

if __name__ == "__main__":
    print("\n--- TwinAI - Log Sentinel 起動 ---")
    print("--- リアルタイムログ監視を開始します (Ctrl+Cで終了) ---")
    event_handler = ChangeHandler(); observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True); observer.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        observer.stop(); print("\n--- 監視を終了します ---")
    observer.join()
    