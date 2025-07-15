import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

print("--- 🤖 AIモデルの訓練を開始します ---")

# --- 1. 学習データの読み込み ---
try:
    # pandasを使い、JSONLファイルを一括で読み込む
    data = pd.read_json('training_data.jsonl', lines=True)
    print(f"\n1. 学習データを読み込みました。 (全{len(data)}件)")
except FileNotFoundError:
    print("[エラー] 'training_data.jsonl'が見つかりません。monitor.pyでデータを収集してください。")
    exit()

# --- 2. データの前処理と特徴量への変換 ---
# AIが理解できるように、ログのテキスト情報を数値（ベクトル）に変換します。
print("\n2. テキストデータをAIが理解できる数値に変換中...")

# "log"列から、AIが注目すべきテキスト情報を抽出する
# ここでは最も重要な'request_first_line'（GET /path HTTP/1.1の部分）を使う
# 'fillna("")'は、万が一データが空だった場合にエラーを防ぐための処理
texts = data['log'].apply(lambda x: x.get('request_first_line', '')).fillna("")

# TF-IDFという手法で、テキストを数値ベクトルに変換する準備
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(texts)

# 正解ラベル（異常か正常か）を取得
y = data['is_anomaly']

print("   ✅ 変換完了。")

# --- 3. 訓練データとテストデータに分割 ---
# データの一部を「テスト用」として取っておき、AIの性能を正しく評価できるようにします。
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\n3. データを訓練用({len(y_train)}件)とテスト用({len(y_test)}件)に分割しました。")

# --- 4. AIモデルの訓練 ---
print("\n4. AIモデル（ロジスティック回帰）の訓練を開始...")
# ロジスティック回帰という、シンプルで解釈しやすい分類モデルを使用
model = LogisticRegression()
model.fit(X_train, y_train)
print("   ✅ 訓練完了！")

# --- 5. モデルの性能評価 ---
print("\n5. 完成したAIモデルの性能をテストデータで評価します。")
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"\n   🎯 正解率 (Accuracy): {accuracy:.2f} ({accuracy*100:.2f}%)")
print("\n   詳細レポート:")
print(classification_report(y_test, y_pred))

# --- 6. 完成したモデルと変換器の保存 ---
# 他のプログラムから呼び出せるように、訓練済みのモデルとVectorizerをファイルに保存
joblib.dump(model, 'log_anomaly_model.joblib')
joblib.dump(vectorizer, 'tfidf_vectorizer.joblib')

print("--- ✅ 全ての処理が完了しました ---")
print(" 'log_anomaly_model.joblib' と 'tfidf_vectorizer.joblib' が保存されました。")