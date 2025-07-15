import json
from datetime import datetime

print("--- テストを開始します ---")

# 1. 日付データを含んだ辞書を作成
my_data = {
    "message": "これはテストです",
    "record_time": datetime.now().isoformat()  # 文字列に変換！
}

print("作成したデータ:")
print(my_data)

# 2. データを 'test.json' というファイルに書き込み
try:
    with open("test.json", "w") as f:
        json.dump(my_data, f, indent=2)
    print("\n✅ 成功: 'test.json' にデータを書き込みました。")
except Exception as e:
    print(f"\n❌ 失敗: ファイルの書き込み中にエラーが発生しました。")
    print(f"   エラー内容: {e}")

print("\n--- テストを終了します ---")