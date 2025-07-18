import json
import os
from datetime import datetime
from zoneinfo import ZoneInfo

# --- 設定 ---
PATH_COUNTS_FILE = "anomalous_path_counts.json"
BLACKLIST_FILE = "blacklist.txt"
WHITELIST_FILE = "whitelist.txt"

def clear_screen():
    """ターミナル画面をクリアする"""
    os.system('cls' if os.name == 'nt' else 'clear')

def load_path_counts():
    """攻撃パスのカウントファイルを読み込む"""
    try:
        with open(PATH_COUNTS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_path_counts(data):
    """攻撃パスのカウントファイルを保存する"""
    with open(PATH_COUNTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def add_to_list_file(filepath, pattern):
    """指定されたリストファイルにパターンを追記する"""
    with open(filepath, "a", encoding='utf-8') as f:
        timestamp = datetime.now(ZoneInfo('Asia/Tokyo')).strftime('%Y-%m-%d %H:%M')
        f.write(f"\n# Judged by human on {timestamp}\n")
        f.write(pattern + "\n")

def main():
    """メインのレビュー処理"""
    clear_screen()
    print("--- 🕵️ 異常検知レビューツール 🕵️ ---")
    
    path_counts = load_path_counts()
    
    if not path_counts:
        print("\nレビュー対象のデータがありません。")
        return

    # 攻撃回数が多い順に並び替え
    sorted_paths = sorted(path_counts.items(), key=lambda item: item[1], reverse=True)
    
    total_items = len(sorted_paths)
    judged_count = 0

    for path, count in sorted_paths:
        judged_count += 1
        clear_screen()
        print("--- 🕵️ 異常検知レビューツール 🕵️ ---")
        print(f"\nレビュー中: {judged_count} / {total_items}")
        print("----------------------------------------------------")
        print(f"攻撃されたパス: {path}")
        print(f"検知回数: {count} 回")
        print("----------------------------------------------------")
        print("このリクエストをどう分類しますか？")
        print("  [1] ブラックリストに追加する (明確な攻撃)")
        print("  [2] ホワイトリストに追加する (安全なアクセス)")
        print("  [3] 何もしない (今回は無視)")
        print("  [4] レビューを中断して保存する")

        choice = input("あなたの判断 [1-4]: ")

        if choice == '1':
            add_to_list_file(BLACKLIST_FILE, path)
            del path_counts[path] # 処理が完了したので辞書から削除
            print(f"✅ '{path}' をブラックリストに追加しました。")
        elif choice == '2':
            add_to_list_file(WHITELIST_FILE, path)
            del path_counts[path] # 処理が完了したので辞書から削除
            print(f"✅ '{path}' をホワイトリストに追加しました。")
        elif choice == '4':
            print("レビューを中断します...")
            break
        else:
            # 「何もしない」を選んだ場合は、辞書には残したまま次の項目へ
            print("➡  今回は無視します。次の項目へ...")
        
        time.sleep(1) # ユーザーがフィードバックを確認する時間

    # 変更をファイルに保存
    save_path_counts(path_counts)
    print("\nレビュー結果を保存しました。")
    print("--- ✅ レビューツールを終了します ---")

if __name__ == "__main__":
    import time
    main()