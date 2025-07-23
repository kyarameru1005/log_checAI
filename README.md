# log_checAI

## 概要
log_checAIは、ApacheなどのWebサーバのアクセスログをリアルタイムで監視し、AIとルールベース（ホワイトリスト・ブラックリスト）による異常検知を行うシステムです。異常なリクエストを検知すると、サンドボックス環境（Docker）上で攻撃の再現・影響分析を自動で実施し、分析結果を記録します。攻撃パスやIPアドレスの集計も行い、セキュリティ運用を支援します。

## 主な機能
- ログファイルのリアルタイム監視
- AIモデルとルールベースによる異常検知
- 攻撃リクエストの自動再現（Dockerサンドボックス）
- ファイルシステムの変化検出・分析レポート生成
- 攻撃パス・IPアドレスの集計
- 人手による攻撃パスのレビュー・分類

## 構築方法
1. **Python 3.10 以上をインストール**
2. **仮想環境の作成・有効化（推奨）**
   ```bash
   python -m venv .venv
   # macOS/Linux
   source .venv/bin/activate
   # Windows
   .venv\Scripts\activate
   ```
3. **必要なパッケージのインストール**
   ```bash
   pip install -r requirements.txt
   ```
   ※ requirements.txt が無い場合:
   ```bash
   pip install watchdog apache-log-parser joblib scikit-learn
   ```
4. **Dockerのインストール**
   - [Docker公式サイト](https://www.docker.com/) からインストール
   - twinai-apache-sandbox イメージを事前にビルドまたは取得
5. **学習済みモデルファイルの配置**
   - `log_anomaly_model.joblib`, `tfidf_vectorizer.joblib` をプロジェクト直下に配置
   - モデルが無い場合は「モデルの作成方法」を参照
6. **監視対象ログのパス設定**
   - `monitor.py` の `WATCH_DIR` を編集

## モデルの作成方法
1. `training_data.jsonl` を編集・追加
2. 以下のコマンドでAIモデルを学習・保存
   ```bash
   python train_model.py
   ```
   - 実行後、`log_anomaly_model.joblib` と `tfidf_vectorizer.joblib` が生成されます
3. モデルの再学習が必要な場合は `retrain_ai.py` を利用

## プログラムの起動方法
1. 監視対象のログファイルやパスを `monitor.py` の `WATCH_DIR` で設定
2. 仮想環境を有効化し、依存パッケージ・モデル・Docker環境が揃っていることを確認
3. 監視プログラムを起動
   ```bash
   python monitor.py
   ```
   - 異常検知時は自動で攻撃再現・分析が行われ、結果が `analysis_results.jsonl` に記録されます

## レビュー機能（人手による判定）
AIやルールで自動検知された攻撃パスを人手で分類・判定できます。

1. 攻撃パスの集計ファイル（`anomalous_path_counts.json`）が存在することを確認
2. 以下のコマンドでレビューツールを起動
   ```bash
   python judge_anomalies.py
   ```
3. 画面の指示に従い、各パスを「ブラックリスト」「ホワイトリスト」「無視」から選択
   - 選択結果は `blacklist.txt` や `whitelist.txt` に自動で追記されます
   - 判定済みのパスはリストから削除されます
4. レビュー結果は自動保存されます

## ライセンス
MIT License 