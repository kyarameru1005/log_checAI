import time
import joblib
import subprocess
import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import apache_log_parser
from pprint import pprint

# --- Configuration (設定) ---
WATCH_DIR = "/var/log/apache2"
LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
parser = apache_log_parser.make_parser(LOG_FORMAT)
ANALYSIS_FILE = "analysis_results.jsonl"

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime): return obj.isoformat()
        return super().default(obj)

# --- ルールとAIモデルの読み込み ---
BLACKLISTED_PATTERNS = ["/.env", "/.git", "/wp-config.php", "etc/passwd", "SELECT", "UNION", "INSERT", "<script>", "/geoserver/"]
def is_anomaly_by_rule(request_line):
    for pattern in BLACKLISTED_PATTERNS:
        if pattern.lower() in request_line.lower(): return True
    return False
try:
    model = joblib.load('log_anomaly_model.joblib')
    vectorizer = joblib.load('tfidf_vectorizer.joblib')
except FileNotFoundError:
    print("[エラー] AIモデルファイルが見つかりません。")
    exit()
def predict_log_anomaly(log_text):
    vectorized_text = vectorizer.transform([log_text])
    prediction = model.predict(vectorized_text)[0]
    return bool(prediction)

# --- 分析シーケンス ---
def trigger_analysis_sequence(log_data, detection_method):
    print(f"--- 🚀 分析シーケンス開始 (検知方法: {detection_method}) ---")
    # (この関数の中身は変更ありません)
    # ...

# --- 状態共有機能を追加したハンドラ ---
class ChangeHandler(FileSystemEventHandler):
    def __init__(self, state):
        self.last_positions = {}
        self.state = state

    def on_modified(self, event):
        if event.is_directory or 'access.log' not in event.src_path: return
        new_lines = []
        try:
            with open(event.src_path, 'r', encoding='utf-8') as f:
                f.seek(self.last_positions.get(event.src_path, 0))
                new_lines = f.readlines()
                self.last_positions[event.src_path] = f.tell()
        except Exception: return

        for line in new_lines:
            if not line.strip(): continue
            try:
                log_data = parser(line)
                request_line = log_data.get('request_first_line', '')
                
                is_detected = False
                detection_method_for_header, detection_method_for_sequence = "", ""

                if is_anomaly_by_rule(request_line):
                    is_detected, detection_method_for_header, detection_method_for_sequence = True, "ルール", "Rule-based"
                elif predict_log_anomaly(request_line):
                    is_detected, detection_method_for_header, detection_method_for_sequence = True, "AI", "AI-based"

                if is_detected:
                    utc_time = log_data.get('time_received_datetimeobj')
                    log_time_str = utc_time.replace(tzinfo=timezone.utc).astimezone(ZoneInfo("Asia/Tokyo")).strftime('%Y-%m-%d %H:%M:%S') if utc_time else "時刻不明"
                    
                    print(f"\n🚨🚨🚨【{detection_method_for_header}で異常を検知】🚨🚨🚨")
                    print(f"発生時刻 (JST): {log_time_str}")
                    pprint(log_data)
                    
                    # 異常を検知したので、正常通知のタイマーをリセット
                    self.state['last_message_time'] = datetime.now()

                    trigger_analysis_sequence(log_data, detection_method_for_sequence)
            except Exception as e:
                print(f"[警告] ログ1行の処理に失敗: {e}")


if __name__ == "__main__":
    print("\n--- TwinAI - Log Sentinel (v1.5 定期通知版) 起動 ---")
    
    # 最後にメッセージを出力した時刻を管理する共有オブジェクト
    shared_state = {
        "last_message_time": datetime.now(),
    }
    
    event_handler = ChangeHandler(shared_state)
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.start()
    
    print("--- 訓練済みAIモデルを読み込みました。---")
    print("--- リアルタイムログ監視を開始します (Ctrl+Cで終了) ---")

    try:
        while True:
            time.sleep(1)
            
            # --- ★★★ ここからが定期正常通知のロジック ★★★ ---
            # 最後にメッセージを出力してから60秒以上経過したか？
            elapsed = (datetime.now() - shared_state["last_message_time"]).total_seconds()
            
            if elapsed > 300:
                jst_now = datetime.now(ZoneInfo("Asia/Tokyo")).strftime('%H:%M:%S')
                print(f"✅ [システム正常] {jst_now}現在、新たな異常は検知されていません。")
                # メッセージを出力したので、タイマーを現在時刻にリセット
                shared_state["last_message_time"] = datetime.now()

    except KeyboardInterrupt:
        observer.stop()
        print("\n--- 監視を終了します ---")
    observer.join()