import time
import joblib
import subprocess
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import apache_log_parser
from pprint import pprint

# --- Configuration ---
WATCH_DIR = "/var/log/apache2"
LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
parser = apache_log_parser.make_parser(LOG_FORMAT)
ANALYSIS_FILE = "analysis_results.jsonl"

# --- ★★★★★ 日付データを自動で文字列に変換する特別クラス ★★★★★ ---
class DateTimeEncoder(json.JSONEncoder):
    """ datetimeオブジェクトをJSONが扱える文字列に変換する """
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

# --- 1. ルールベースのブラックリスト ---
BLACKLISTED_PATTERNS = [
    "/.env", "/.git", "/wp-config.php", "etc/passwd",
    "SELECT", "UNION", "INSERT", "<script>", "/geoserver/",
]

def is_anomaly_by_rule(request_line):
    for pattern in BLACKLISTED_PATTERNS:
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
    print("[エラー] AIモデルファイルが見つかりません。train_model.py を実行してください。")
    exit()

# --- 3. AIによる予測関数 ---
def predict_log_anomaly(log_text):
    vectorized_text = vectorizer.transform([log_text])
    prediction = model.predict(vectorized_text)[0]
    return bool(prediction)

# --- 分析シーケンス（サンドボックス起動〜記録）---
def trigger_analysis_sequence(log_data, detection_method):
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

    reproduce_output = ""
    try:
        print(f"\n2. コンテナ {container_id[:12]} に対して攻撃を再現中...")
        request_path = log_data.get('request_first_line', '').split()[1]
        reproduce_command = ["docker", "exec", container_id, "curl", f"http://localhost:80{request_path}"]
        reproduce_result = subprocess.run(reproduce_command, capture_output=True, text=True, check=False)
        reproduce_output = reproduce_result.stdout if reproduce_result.stdout else reproduce_result.stderr
        print("   ✅ 再現完了。")
    except Exception as e:
        reproduce_output = f"再現エラー: {e}"
        print(f"[エラー] 攻撃の再現に失敗: {e}")

    try:
        print(f"\n3. 分析結果を {ANALYSIS_FILE} に記録中...")
        analysis_record = {
            "analysis_timestamp": datetime.now().isoformat(),
            "detection_method": detection_method,
            "original_log": log_data,
            "reproduction_result": reproduce_output.strip()
        }
        with open(ANALYSIS_FILE, "a") as f:
            # ↓↓↓ ここをDateTimeEncoderクラスを使うように修正しました！ ↓↓↓
            f.write(json.dumps(analysis_record, cls=DateTimeEncoder) + "\n")
        print("   ✅ 記録完了。")
    except Exception as e:
        print(f"[エラー] 結果の記録に失敗: {e}")

    finally:
        if container_id:
            print("\n4. サンドボックス環境を破棄します。")
            subprocess.run(["docker", "stop", container_id], capture_output=True, text=True)

class ChangeHandler(FileSystemEventHandler):
    def __init__(self): self.last_positions = {}
    def on_modified(self, event):
        if event.is_directory or 'access.log' not in event.src_path: return
        try:
            with open(event.src_path, 'r', encoding='utf-8') as f:
                f.seek(self.last_positions.get(event.src_path, 0))
                new_lines = f.readlines()
                self.last_positions[event.src_path] = f.tell()
            for line in new_lines:
                if not line.strip(): continue
                try:
                    log_data = parser(line)
                    request_line = log_data.get('request_first_line', '')
                    
                    if is_anomaly_by_rule(request_line):
                        print("\n🚨🚨🚨【ルールで異常を検知】🚨🚨🚨")
                        pprint(log_data)
                        trigger_analysis_sequence(log_data, "Rule-based")
                    elif predict_log_anomaly(request_line):
                        print("\n🚨🚨🚨【AIが異常を検知】🚨🚨🚨")
                        pprint(log_data)
                        trigger_analysis_sequence(log_data, "AI-based")
                    else:
                        # 正常なログは大量に出力されるため、簡潔に表示
                        # print(f"✅ [正常] {request_line}")
                        pass
                except Exception: pass
        except Exception: pass

if __name__ == "__main__":
    print("\n--- TwinAI - Log Sentinel (完全自動モード) 起動 ---")
    event_handler = ChangeHandler(); observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True); observer.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        observer.stop(); print("\n--- 監視を終了します ---")
    observer.join()