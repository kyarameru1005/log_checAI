import pandas as pd
import joblib
import json
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
import os

print("--- 🧠 AIモデルの継続的学習を開始します ---")

# --- 1. 全ての学習データを読み込む ---
all_records = []
# 1-1. 元々の学習データを読み込む
try:
    with open('training_data.jsonl', 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                all_records.append(json.loads(line))
    print(f"✅ 元の学習データを読み込みました。({len(all_records)}件)")
except FileNotFoundError:
    print("[情報] 'training_data.jsonl' が見つかりませんでした。新規作成します。")

# 1-2. 新しく蓄積された分析結果を読み込む
new_knowledge_count = 0
try:
    with open('analysis_results.jsonl', 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                # 'analysis_results.jsonl'の形式を学習データ形式に変換
                analysis_data = json.loads(line)
                new_record = {
                    "log": analysis_data.get("original_log"),
                    "is_anomaly": True # 分析されたものは全て異常
                }
                all_records.append(new_record)
                new_knowledge_count += 1
    print(f"✅ 新しい知識(analysis_results.jsonl)を読み込みました。({new_knowledge_count}件)")
except FileNotFoundError:
    print("[情報] 'analysis_results.jsonl' はまだありません。スキップします。")

if not all_records:
    print("[エラー] 学習するためのデータが1件もありません。")
    exit()

print(f"   => 合計 {len(all_records)} 件のデータで再学習を行います。")
data = pd.DataFrame(all_records)

# --- 2. データの前処理と特徴量への変換 (train_model.pyと同じ) ---
print("\n2. テキストデータをAIが理解できる数値に変換中...")
texts = data['log'].apply(lambda x: x.get('request_first_line', '') if isinstance(x, dict) else '').fillna("")
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(texts)
y = data['is_anomaly']
print("   ✅ 変換完了。")

# --- 3. 訓練データとテストデータに分割 ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\n3. データを訓練用({len(y_train)}件)とテスト用({len(y_test)}件)に分割しました。")

# --- 4. AIモデルの再訓練 ---
print("\n4. AIモデルの再訓練を開始...")
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)
print("   ✅ 再訓練完了！")

# --- 5. モデルの性能評価 ---
print("\n5. 進化したAIモデルの性能を評価します。")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\n   🎯 正解率 (Accuracy): {accuracy:.2f} ({accuracy*100:.2f}%)")
print("\n   詳細レポート:")
print(classification_report(y_test, y_pred, zero_division=0))

# --- 6. 進化したモデルと変換器で古いものを上書き保存 ---
joblib.dump(model, 'log_anomaly_model.joblib')
joblib.dump(vectorizer, 'tfidf_vectorizer.joblib')

print("--- ✅ 全ての処理が完了しました ---")
print("進化したAIモデルで 'log_anomaly_model.joblib' と 'tfidf_vectorizer.joblib' を上書き保存しました。")