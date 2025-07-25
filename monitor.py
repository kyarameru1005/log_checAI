#!/home/kyarameru/log_checAI/.venv/bin/python
# --- 必要なライブラリのインポート ---
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
WATCH_DIR = "/var/log/apache2"  # 監視対象のディレクトリ（Apacheログディレクトリ）
LOG_FORMAT = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""  # Apacheログの書式
parser = apache_log_parser.make_parser(LOG_FORMAT)  # ログパーサの作成
ANALYSIS_FILE = "analysis_results.jsonl"  # 分析結果の保存ファイル
IP_COUNTS_FILE = "ip_access_counts.json"  # IPごとのアクセス回数保存ファイル
ANOMALOUS_PATH_COUNTS_FILE = "anomalous_path_counts.json"  # 攻撃パスの回数を記録するファイル

# --- 日時をJSONで扱うためのエンコーダ ---
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime): return obj.isoformat()
        return super().default(obj)

# --- 外部リスト（ホワイトリスト・ブラックリスト）の読み込み関数 ---
def load_list_from_file(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        return []

WHITELIST_PATTERNS = load_list_from_file('whitelist.txt')  # ホワイトリストパターンの読み込み
BLACKLIST_PATTERNS = load_list_from_file('blacklist.txt')  # ブラックリストパターンの読み込み

# --- AIモデルとベクトライザの読み込み ---
try:
    model = joblib.load('log_anomaly_model.joblib')  # 異常検知モデル
    vectorizer = joblib.load('tfidf_vectorizer.joblib')  # テキストベクトライザ
except FileNotFoundError:
    print("[エラー] AIモデルファイルが見つかりません。train_model.pyを先に実行してください。")
    exit()

# --- ホワイトリスト判定関数 ---
def is_whitelisted(request_line):
    """リクエストがホワイトリストに該当するか判定"""
    for pattern in WHITELIST_PATTERNS:
        if pattern.lower() in request_line.lower(): return True
    return False

# --- ブラックリスト判定関数 ---
def is_blacklisted(request_line):
    """リクエストがブラックリストに該当するか判定"""
    for pattern in BLACKLIST_PATTERNS:
        if pattern.lower() in request_line.lower(): return True
    return False

# --- AIによる異常判定関数 ---
def predict_log_anomaly(log_text):
    """AIモデルでリクエストの異常判定を行う"""
    vectorized_text = vectorizer.transform([log_text])
    prediction = model.predict(vectorized_text)[0]
    return bool(prediction)

# --- 攻撃検知時の分析シーケンス ---
def trigger_analysis_sequence(log_data, detection_method):
    """攻撃検知時にサンドボックスで再現・分析し、結果を記録する"""
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

# --- ファイル監視イベントハンドラ ---
class ChangeHandler(FileSystemEventHandler):
    def __init__(self, state, ip_counts, path_counts):
        self.last_positions = {}  # 各ファイルの最終読み取り位置を記録
        self.state = state  # 共有状態（最終メッセージ時刻など）
        self.ip_counts = ip_counts  # IPごとのアクセス回数辞書
        self.path_counts = path_counts # 攻撃パスカウント用の辞書

    def on_modified(self, event):
        # access.logファイルの変更のみ処理
        if event.is_directory or 'access.log' not in event.src_path: return
        try:
            with open(event.src_path, 'r', encoding='utf-8') as f:
                f.seek(self.last_positions.get(event.src_path, 0))
                new_lines = f.readlines()
                self.last_positions[event.src_path] = f.tell()
        except Exception: return

        for line in new_lines:
            if not line.strip(): continue
            try:
                log_data = parser(line)  # ログ1行をパース
                ip_address = log_data.get('remote_host')
                if ip_address:
                    self.ip_counts[ip_address] = self.ip_counts.get(ip_address, 0) + 1  # IPごとにカウント
                
                request_line = log_data.get('request_first_line', '')
                if is_whitelisted(request_line):
                    self.state['last_message_time'] = datetime.now()
                    continue

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

                    # --- 攻撃されたパスをカウントアップ ---
                    request_path = log_data.get('request_url_path')
                    if request_path:
                        self.path_counts[request_path] = self.path_counts.get(request_path, 0) + 1

                    trigger_analysis_sequence(log_data, detection_method)
            except Exception as e:
                print(f"[警告] ログ1行の処理に失敗: {e}")

if __name__ == "__main__":
    print("\n--- TwinAI - Log Sentinel (v2.5 攻撃パス集計版) 起動 ---")

    # --- 起動時にIPとパスのカウントファイルを読み込む ---
    ip_counts_data = {}
    path_counts_data = {}
    try:
        with open(IP_COUNTS_FILE, 'r', encoding='utf-8') as f: ip_counts_data = json.load(f)
        print("--- 過去のIPアクセス履歴を読み込みました ---")
    except (FileNotFoundError, json.JSONDecodeError):
        print("--- IPアクセス履歴ファイルが見つからないため、新規に作成します ---")
    try:
        with open(ANOMALOUS_PATH_COUNTS_FILE, 'r', encoding='utf-8') as f: path_counts_data = json.load(f)
        print("--- 過去の攻撃パス履歴を読み込みました ---")
    except (FileNotFoundError, json.JSONDecodeError):
        print("--- 攻撃パス履歴ファイルが見つからないため、新規に作成します ---")

    shared_state = {"last_message_time": datetime.now()}
    event_handler = ChangeHandler(shared_state, ip_counts_data, path_counts_data)
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.start()
    
    print("--- リアルタイムログ監視を開始します (Ctrl+Cで終了) ---")

    try:
        while True:
            time.sleep(1)
            elapsed = (datetime.now() - shared_state["last_message_time"]).total_seconds()
            if elapsed > 60:
                try:
                    jst_now = datetime.now(ZoneInfo("Asia/Tokyo")).strftime('%H:%M:%S')
                    print(f"✅ [システム正常] {jst_now}現在、新たな異常は検知されていません。")
                    shared_state["last_message_time"] = datetime.now()
                    with open(IP_COUNTS_FILE, 'w', encoding='utf-8') as f: json.dump(ip_counts_data, f, indent=4)
                    with open(ANOMALOUS_PATH_COUNTS_FILE, 'w', encoding='utf-8') as f: json.dump(path_counts_data, f, indent=4)
                except Exception as e:
                    print(f"[DEBUG][例外] 1分ごと出力処理で例外: {e}")

    except KeyboardInterrupt:
        print("\n--- 監視を終了します。最終結果を保存中... ---")
    except Exception as e:
        print(f"[DEBUG][例外] メインループで例外: {e}")
    finally:
        # --- 終了時に最終的なIPとパスのカウントを保存 ---
        with open(IP_COUNTS_FILE, 'w', encoding='utf-8') as f:
            sorted_ips = dict(sorted(ip_counts_data.items(), key=lambda item: item[1], reverse=True))
            json.dump(sorted_ips, f, indent=4)
        with open(ANOMALOUS_PATH_COUNTS_FILE, 'w', encoding='utf-8') as f:
            sorted_paths = dict(sorted(path_counts_data.items(), key=lambda item: item[1], reverse=True))
            json.dump(sorted_paths, f, indent=4)
        print("--- IPアクセス回数と攻撃パス回数の保存が完了しました。 ---")
        observer.stop()
        
    observer.join()