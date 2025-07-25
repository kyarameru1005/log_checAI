# --- 必要なライブラリのインポート ---
import pandas as pd
import joblib
import json # jsonライブラリを直接使うためにインポート
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

print("--- 🤖 AIモデルの訓練を開始します ---")

# --- 1. 学習データの読み込み (より堅牢な方法) ---
records = []
try:
    # 1行ずつファイルを読み、手動でJSONをパースする
    with open('training_data.jsonl', 'r', encoding='utf-8') as f:
        for line in f:
            # 空行は無視する
            if line.strip():
                records.append(json.loads(line))
    
    # パースしたデータのリストからDataFrameを作成
    data = pd.DataFrame(records)
    print(f"\n1. 学習データを読み込みました。 (全{len(data)}件)")

except FileNotFoundError:
    print("[エラー] 'training_data.jsonl'が見つかりません。monitor.pyでデータを収集してください。")
    exit()
except json.JSONDecodeError as e:
    print(f"\n[エラー] 'training_data.jsonl'の読み込み中にJSONエラーが発生しました。")
    print(f"ファイルが破損している可能性があります。破損行の近くでエラー: {e}")
    print("一度 'training_data.jsonl' を削除し、再度データ収集からやり直してみてください。")
    exit()


# --- 2. データの前処理と特徴量への変換 ---
print("\n2. テキストデータをAIが理解できる数値に変換中...")
# 各レコードのリクエスト1行目を抽出し、空欄は空文字列で埋める
texts = data['log'].apply(lambda x: x.get('request_first_line', '')).fillna("")
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(texts)
y = data['is_anomaly']
print("   ✅ 変換完了。")

# --- 3. 訓練データとテストデータに分割 ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\n3. データを訓練用({len(y_train)}件)とテスト用({len(y_test)}件)に分割しました。")

# --- 4. AIモデルの訓練 ---
print("\n4. AIモデル（ロジスティック回帰）の訓練を開始...")
# max_iterを増やして収束しやすくする
model = LogisticRegression(max_iter=1000) # 収束しやすくするためにmax_iterを増やす
model.fit(X_train, y_train)
print("   ✅ 訓練完了！")

# --- 5. モデルの性能評価 ---
print("\n5. 完成したAIモデルの性能をテストデータで評価します。")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\n   🎯 正解率 (Accuracy): {accuracy:.2f} ({accuracy*100:.2f}%)")
print("\n   詳細レポート:")
# zero_division=0 を追加して、データが少ない場合の警告を抑制
print(classification_report(y_test, y_pred, zero_division=0))

# --- 6. 完成したモデルと変換器の保存 ---
# 訓練済みモデルとベクトライザをファイルに保存
joblib.dump(model, 'log_anomaly_model.joblib')
joblib.dump(vectorizer, 'tfidf_vectorizer.joblib')

print("\n--- ✅ 全ての処理が完了しました ---")
print(" 'log_anomaly_model.joblib' と 'tfidf_vectorizer.joblib' が保存されました。")