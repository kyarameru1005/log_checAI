import time
import joblib
import subprocess
import json
from datetime import datetime
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

# --- 1. ルールベースのブラックリスト ---
BLACKLISTED_PATTERNS = [
    "/.env", "/.git", "/wp-config.php", "etc/passwd",
    "SELECT", "UNION", "INSERT", "<script>", "/geoserver/",
]

def is_anomaly_by_rule(request_line):
    for pattern in BLACKLISTED_PATTERNS:
        if pattern.lower() in request_line.lower(): return True
    return False

# --- 2. 訓練済みAIモデルの読み込み ---
try:
    print("--- 訓練済みAIモデルを読み込んでいます... ---")
    model = joblib.load('log_anomaly_model.joblib')
    vectorizer = joblib.load('tfidf_vectorizer.joblib')
    print("   ✅ AIモデルの準備完了。")
except FileNotFoundError:
    print("[エラー] AIモデルファイルが見つかりません。")
    exit()

# --- 3. AIによる予測関数 ---
def predict_log_anomaly(log_text):
    vectorized_text = vectorizer.transform([log_text])
    prediction = model.predict(vectorized_text)[0]
    return bool(prediction)

# --- 分析シーケンス（サンドボックス起動〜記録）---
def trigger_analysis_sequence(log_data, detection_method):
    print(f"--- 🚀 分析シーケンス開始 (検知方法: {detection_method}) ---")
    # ... (この関数の中身は変更ありません)
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
            "analysis_timestamp": datetime.now().isoformat(),
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

class ChangeHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_positions = {}

    def on_modified(self, event):
        if event.is_directory or 'access.log' not in event.src_path:
            return

        new_lines = []
        try:
            with open(event.src_path, 'r', encoding='utf-8') as f:
                f.seek(self.last_positions.get(event.src_path, 0))
                new_lines = f.readlines()
                self.last_positions[event.src_path] = f.tell()
        except Exception as e:
            print(f"[エラー] ログファイルの読み込みに失敗しました: {e}")
            return

        for line in new_lines:
            if not line.strip():
                continue
            
            try:
                log_data = parser(line)
                request_line = log_data.get('request_first_line', '')
                
                # --- ★★★★★ ここからが修正箇所 ★★★★★ ---
                def print_anomaly_header(detection_method):
                    """異常検知時のヘッダー（時刻情報を含む）を表示する"""
                    log_time_str = log_data.get('time_received_isoformat', '時刻不明').replace('T', ' ')
                    print(f"\n🚨🚨🚨【{detection_method}で異常を検知】🚨🚨🚨")
                    print(f"発生時刻: {log_time_str}")
                    pprint(log_data)

                if is_anomaly_by_rule(request_line):
                    print_anomaly_header("ルール")
                    trigger_analysis_sequence(log_data, "Rule-based")
                elif predict_log_anomaly(request_line):
                    print_anomaly_header("AI")
                    trigger_analysis_sequence(log_data, "AI-based")
                
            except Exception as e:
                print(f"[警告] ログ1行の処理に失敗しました。スキップします。エラー: {e}")

if __name__ == "__main__":
    print("\n--- TwinAI - Log Sentinel (v1.2 時刻表示版) 起動 ---")
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