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

# --- AIモデルと分析関数 (これらはグローバルに配置) ---
try:
    print("--- 訓練済みAIモデルを読み込んでいます... ---")
    model = joblib.load('log_anomaly_model.joblib')
    vectorizer = joblib.load('tfidf_vectorizer.joblib')
    print("   ✅ AIモデルの準備完了。")
except FileNotFoundError:
    print("[エラー] AIモデルファイルが見つかりません。train_model.pyを先に実行してください。")
    exit()

def predict_log_anomaly(log_text):
    vectorized_text = vectorizer.transform([log_text])
    prediction = model.predict(vectorized_text)[0]
    return bool(prediction)

def trigger_analysis_sequence(log_data, detection_method):
    # この関数の中身は変更ありません
    print(f"--- 🚀 分析シーケンス開始 (検知方法: {detection_method}) ---")
    # ... (処理内容は同じなので省略)

# --- ★★★ バグを修正したファイル監視ハンドラ ★★★ ---
class ChangeHandler(FileSystemEventHandler):
    def __init__(self, state):
        self.last_positions = {}
        self.state = state
        # --- クラスのインスタンスに直接リストを読み込む ---
        print("--- ホワイトリストとブラックリストを読み込んでいます... ---")
        self.whitelist = self._load_list_from_file('whitelist.txt')
        self.blacklist = self._load_list_from_file('blacklist.txt')
        print(f"   ✅ ホワイトリスト読み込み完了: {len(self.whitelist)}件")
        print(f"   ✅ ブラックリスト読み込み完了: {len(self.blacklist)}件")

    def _load_list_from_file(self, filename):
        """ファイルからリストを読み込むヘルパーメソッド"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"[情報] '{filename}' が見つかりませんでした。リストは空として扱います。")
            return []

    def _is_whitelisted(self, request_line):
        """インスタンスのホワイトリストと照合する"""
        for pattern in self.whitelist:
            if pattern.lower() in request_line.lower(): return True
        return False

    def _is_blacklisted(self, request_line):
        """インスタンスのブラックリストと照合する"""
        for pattern in self.blacklist:
            if pattern.lower() in request_line.lower(): return True
        return False

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
                
                if self._is_whitelisted(request_line):
                    self.state['last_message_time'] = datetime.now()
                    continue

                is_detected, detection_method = False, ""
                if self._is_blacklisted(request_line):
                    is_detected, detection_method = True, "ブラックリスト"
                elif predict_log_anomaly(request_line):
                    is_detected, detection_method = True, "AI"

                if is_detected:
                    utc_time = log_data.get('time_received_datetimeobj')
                    log_time_str = utc_time.replace(tzinfo=timezone.utc).astimezone(ZoneInfo("Asia/Tokyo")).strftime('%Y-%m-%d %H:%M:%S') if utc_time else "時刻不明"
                    
                    print(f"\n🚨🚨🚨【{detection_method}で異常を検知】🚨🚨🚨")
                    print(f"発生時刻 (JST): {log_time_str}")
                    pprint(log_data)
                    
                    self.state['last_message_time'] = datetime.now()
                    trigger_analysis_sequence(log_data, detection_method)
            except Exception as e:
                print(f"[警告] ログ1行の処理に失敗しました。エラー: {e}")


if __name__ == "__main__":
    print("\n--- TwinAI - Log Sentinel (v2.1 修正版) 起動 ---")
    
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
                print(f"✅ [システム正常] {jst_now}現在、1分間新たな異常は検知されていません。")
                shared_state["last_message_time"] = datetime.now()
    except KeyboardInterrupt:
        observer.stop()
        print("\n--- 監視を終了します ---")
    observer.join()