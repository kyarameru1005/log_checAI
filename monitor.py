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
IP_COUNTS_FILE = "ip_access_counts.json" # ★★★ IPカウントを保存するファイル ★★★

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime): return obj.isoformat()
        return super().default(obj)

# --- 外部リストの読み込み ---
def load_list_from_file(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        return []

WHITELIST_PATTERNS = load_list_from_file('whitelist.txt')
BLACKLIST_PATTERNS = load_list_from_file('blacklist.txt')

# --- AIモデルの読み込み ---
try:
    model = joblib.load('log_anomaly_model.joblib')
    vectorizer = joblib.load('tfidf_vectorizer.joblib')
except FileNotFoundError:
    print("[エラー] AIモデルファイルが見つかりません。")
    exit()

# (検知関数や分析シーケンスは変更ありません)
def is_whitelisted(request_line): # ...
def is_blacklisted(request_line): # ...
def predict_log_anomaly(log_text): # ...
def trigger_analysis_sequence(log_data, detection_method): #...

# --- ★★★ IPカウント機能を追加したハンドラ ★★★ ---
class ChangeHandler(FileSystemEventHandler):
    def __init__(self, state, ip_counts):
        self.last_positions = {}
        self.state = state
        self.ip_counts = ip_counts # IPカウント用の辞書を受け取る

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
                
                # --- ★★★ IPアドレスをカウントアップ ★★★ ---
                ip_address = log_data.get('remote_host')
                if ip_address:
                    self.ip_counts[ip_address] = self.ip_counts.get(ip_address, 0) + 1
                
                # ホワイトリストを最優先でチェック
                if is_whitelisted(request_line):
                    self.state['last_message_time'] = datetime.now()
                    continue

                # ブラックリストとAIで異常を検知
                is_detected, detection_method = False, ""
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
                    
                    self.state['last_message_time'] = datetime.now()
                    trigger_analysis_sequence(log_data, detection_method)
            except Exception as e:
                print(f"[警告] ログ1行の処理に失敗: {e}")

if __name__ == "__main__":
    print("\n--- TwinAI - Log Sentinel (v2.2 IPカウント版) 起動 ---")

    # --- ★★★ 起動時にIPカウントファイルを読み込む ★★★ ---
    ip_counts_data = {}
    try:
        with open(IP_COUNTS_FILE, 'r', encoding='utf-8') as f:
            ip_counts_data = json.load(f)
        print(f"--- 過去のIPアクセス履歴を読み込みました ---")
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"--- IPアクセス履歴ファイルが見つからないため、新規に作成します ---")

    shared_state = { "last_message_time": datetime.now() }
    event_handler = ChangeHandler(shared_state, ip_counts_data)
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
                # --- ★★★ 定期的にIPカウントを保存（任意） ★★★ ---
                with open(IP_COUNTS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(ip_counts_data, f, indent=4)

    except KeyboardInterrupt:
        print("\n--- 監視を終了します。最終結果を保存中... ---")
    finally:
        # --- ★★★ 終了時に最終的なIPカウントを保存 ★★★ ---
        with open(IP_COUNTS_FILE, 'w', encoding='utf-8') as f:
            # アクセス回数が多い順に並び替えて保存
            sorted_counts = dict(sorted(ip_counts_data.items(), key=lambda item: item[1], reverse=True))
            json.dump(sorted_counts, f, indent=4)
        print("--- IPアクセス回数の保存が完了しました。 ---")
        observer.stop()
        
    observer.join()