import time
import joblib
import subprocess
import json
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import apache_log_parser
from pprint import pprint

# --- Configuration (設定) ---
# ... (このセクションは変更ありません)
WATCH_DIR = "/var/log/apache2"
LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
parser = apache_log_parser.make_parser(LOG_FORMAT)
ANALYSIS_FILE = "analysis_results.jsonl"

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime): return obj.isoformat()
        return super().default(obj)

# --- ルールとAIモデルの読み込み (変更ありません) ---
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

# --- 分析シーケンス (変更ありません) ---
def trigger_analysis_sequence(log_data, detection_method):
    # (この関数の中身は変更ありません)
    print(f"--- 🚀 分析シーケンス開始 (検知方法: {detection_method}) ---")
    container_id = None
    try:
        print("1. Apacheサンドボックス環境を起動中...")
        command = ["docker", "run", "-d", "--rm", "twinai-apache-sandbox"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        container_id = result.stdout.strip()
        print(f"   ✅ 起動成功 (コンテナID: {container_id[:12]})")
    except Exception as e:
        print(f"[エラー] サンドボックスの起動に失敗: {e}")
        return
    reproduce_output, filesystem_changes = "", ""
    try:
        print(f"\n2. コンテナに対して攻撃を再現中...")
        request_path = log_data.get('request_first_line', '').split()[1]
        reproduce_command = ["docker", "exec", container_id, "curl", f"http://localhost:80{request_path}"]
        reproduce_result = subprocess.run(reproduce_command, capture_output=True, text=True, check=False)
        reproduce_output = reproduce_result.stdout.strip() if reproduce_result.stdout else reproduce_result.stderr.strip()
        print("   ✅ 再現完了。")
    except Exception as e:
        reproduce_output = f"再現エラー: {e}"
    try:
        print("\n3. サンドボックス内のファイルシステムの変化を観察中...")
        diff_command = ["docker", "diff", container_id]
        diff_result = subprocess.run(diff_command, capture_output=True, text=True, check=True)
        filesystem_changes = diff_result.stdout.strip()
        print("   ✅ 観察完了。")
    except Exception as e:
        filesystem_changes = f"差分検知エラー: {e}"
    try:
        print(f"\n4. 分析結果を {ANALYSIS_FILE} に記録中...")
        analysis_record = {
            "analysis_timestamp": datetime.now(ZoneInfo("Asia/Tokyo")).isoformat(),
            "detection_method": detection_method,
            "original_log": log_data,
            "reproduction_result": reproduce_output,
            "filesystem_changes": filesystem_changes.split('\n') if filesystem_changes else []
        }
        with open(ANALYSIS_FILE, "a") as f:
            f.write(json.dumps(analysis_record, cls=DateTimeEncoder) + "\n")
        print("   ✅ 記録完了。")
    except Exception as e:
        print(f"[エラー] 結果の記録に失敗: {e}")
    finally:
        if container_id:
            print("\n5. サンドボックス環境を破棄します。")
            subprocess.run(["docker", "stop", container_id], capture_output=True, text=True)

# --- ★★★ 状態共有機能を追加したハンドラ ★★★ ---
class ChangeHandler(FileSystemEventHandler):
    def __init__(self, state):
        self.last_positions = {}
        # メインループと状態を共有するための変数
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
                detection_method_for_header = ""
                detection_method_for_sequence = ""

                if is_anomaly_by_rule(request_line):
                    is_detected = True
                    detection_method_for_header = "ルール"
                    detection_method_for_sequence = "Rule-based"
                elif predict_log_anomaly(request_line):
                    is_detected = True
                    detection_method_for_header = "AI"
                    detection_method_for_sequence = "AI-based"

                if is_detected:
                    utc_time = log_data.get('time_received_datetimeobj')
                    log_time_str = utc_time.replace(tzinfo=timezone.utc).astimezone(ZoneInfo("Asia/Tokyo")).strftime('%Y-%m-%d %H:%M:%S') if utc_time else "時刻不明"
                    
                    print(f"\n🚨🚨🚨【{detection_method_for_header}で異常を検知】🚨🚨🚨")
                    print(f"発生時刻 (JST): {log_time_str}")
                    pprint(log_data)
                    
                    # 異常を検知したので、メインループに時刻を通知
                    self.state['last_anomaly_time'] = datetime.now()
                    self.state['quiet_period_notified'] = False # 通知フラグをリセット

                    trigger_analysis_sequence(log_data, detection_method_for_sequence)

            except Exception as e:
                print(f"[警告] ログ1行の処理に失敗: {e}")

if __name__ == "__main__":
    print("\n--- TwinAI - Log Sentinel (v1.4 正常通知版) 起動 ---")
    
    # 異常検知の最終時刻と、通知済みかを管理する共有オブジェクト
    shared_state = {
        "last_anomaly_time": None,
        "quiet_period_notified": True, # 最初は通知済みとして扱う
    }
    
    event_handler = ChangeHandler(shared_state)
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.start()
    
    print("--- 訓練済みAIモデルを読み込みました。---")
    print("--- リアルタイムログ監視を開始します (Ctrl+Cで終了) ---")

    try:
        while True:
            # 1秒ごとにチェック
            time.sleep(1)
            
            # --- ここからが正常通知のロジック ---
            # 一度でも異常が検知されたことがあるか？
            if shared_state["last_anomaly_time"] is not None:
                # 最後の異常検知から60秒以上経過したか？
                elapsed = (datetime.now() - shared_state["last_anomaly_time"]).total_seconds()
                # 60秒以上経過し、かつまだ「正常です」と通知していない場合
                if elapsed > 60 and not shared_state["quiet_period_notified"]:
                    jst_now = datetime.now(ZoneInfo("Asia/Tokyo")).strftime('%H:%M:%S')
                    print(f"\n✅ [システム正常] {jst_now}現在、1分間新たな異常は検知されていません。")
                    # 一度通知したら、次の異常が起きるまで通知しないようにフラグを立てる
                    shared_state["quiet_period_notified"] = True

    except KeyboardInterrupt:
        observer.stop()
        print("\n--- 監視を終了します ---")
    observer.join()