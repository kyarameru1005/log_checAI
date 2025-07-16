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

# --- 設定 ---
WATCH_DIR = "/var/log/apache2"
LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
parser = apache_log_parser.make_parser(LOG_FORMAT)
ANALYSIS_FILE = "analysis_results.jsonl"

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime): return obj.isoformat()
        return super().default(obj)

# --- ★★★ 外部リストの読み込み ★★★ ---
def load_list_from_file(filename):
    """ファイルからキーワードのリストを読み込む関数"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            # ファイルを1行ずつ読み込み、コメントや空行を無視する
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        # ファイルが存在しない場合は空のリストを返す
        print(f"[情報] '{filename}' が見つかりませんでした。リストは空として扱います。")
        return []

print("--- ホワイトリストとブラックリストを読み込んでいます... ---")
WHITELIST_PATTERNS = load_list_from_file('whitelist.txt')
BLACKLIST_PATTERNS = load_list_from_file('blacklist.txt')
print(f"   ✅ ホワイトリスト読み込み完了: {len(WHITELIST_PATTERNS)}件")
print(f"   ✅ ブラックリスト読み込み完了: {len(BLACKLIST_PATTERNS)}件")

# --- 検知ロジック関数 ---
def is_whitelisted(request_line):
    for pattern in WHITELIST_PATTERNS:
        if pattern.lower() in request_line.lower(): return True
    return False

def is_blacklisted(request_line):
    for pattern in BLACKLISTED_PATTERNS:
        if pattern.lower() in request_line.lower(): return True
    return False

# --- AIモデルの読み込み ---
try:
    print("--- 訓練済みAIモデルを読み込んでいます... ---")
    model = joblib.load('log_anomaly_model.joblib')
    vectorizer = joblib.load('tfidf_vectorizer.joblib')
    print("   ✅ AIモデルの準備完了。")
except FileNotFoundError:
    print("[エラー] AIモデルファイルが見つかりません。train_model.pyを実行してください。")
    exit()

def predict_log_anomaly(log_text):
    vectorized_text = vectorizer.transform([log_text])
    prediction = model.predict(vectorized_text)[0]
    return bool(prediction)

# --- 分析シーケンス (この関数は変更ありません) ---
def trigger_analysis_sequence(log_data, detection_method):
    print(f"--- 🚀 分析シーケンス開始 (検知方法: {detection_method}) ---")
    # ... (中身は同じなので省略)

# --- ファイル監視ハンドラ ---
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
                
                # --- ★★★ 新しい検知ロジック ★★★ ---
                # 1. ホワイトリストを最優先でチェック
                if is_whitelisted(request_line):
                    # 正常なのでタイマーをリセットして次のログへ
                    self.state['last_message_time'] = datetime.now()
                    continue

                # 2. ブラックリストとAIで異常を検知
                is_detected = False
                detection_method = ""
                
                if is_blacklisted(request_line):
                    is_detected, detection_method = True, "ブラックリスト"
                elif predict_log_anomaly(request_line):
                    is_detected, detection_method = True, "AI"

                if is_detected:
                    utc_time = log_data.get('time_received_datetimeobj')
                    log_time_str = utc_time.replace(tzinfo=timezone.utc).astimezone(ZoneInfo("Asia/Tokyo")).strftime('%Y-%m-%d %H:%M:%S') if utc_time else "時刻不明"
                    
                    print(f"\n🚨🚨🚨【{detection_method}で異常を検知】🚨🚨🚨")
                    print(f"発生時刻 (JST): {log_time_str}")
                    pprint(log_data)
                    
                    # 異常検知なのでタイマーをリセット
                    self.state['last_message_time'] = datetime.now()
                    trigger_analysis_sequence(log_data, detection_method)
            except Exception as e:
                print(f"[警告] ログ1行の処理に失敗しました。エラー: {e}")


if __name__ == "__main__":
    print("\n--- TwinAI - Log Sentinel (v2.0 外部リスト版) 起動 ---")
    
    shared_state = { "last_message_time": datetime.now() }
    event_handler = ChangeHandler(shared_state)
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.start()
    
    print("--- リアルタイムログ監視を開始します (Ctrl+Cで終了) ---")

    try:
        while True:
            time.sleep(1)
            elapsed = (datetime.now() - shared_state["last_message_time"]).total_seconds()
            if elapsed > 60:
                jst_now = datetime.now(ZoneInfo("Asia/Tokyo")).strftime('%H:%M:%S')
                print(f"✅ [システム正常] {jst_now}現在、新たな異常は検知されていません。")
                shared_state["last_message_time"] = datetime.now()
    except KeyboardInterrupt:
        observer.stop()
        print("\n--- 監視を終了します ---")
    observer.join()