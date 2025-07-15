from flask import Flask
import pandas as pd
import json

app = Flask(__name__)

@app.route('/')
def dashboard():
    # ここで analysis_results.jsonl を読み込んで、
    # HTMLとして表示する処理を書く
    try:
        data = pd.read_json('analysis_results.jsonl', lines=True)
        # DataFrameをHTMLテーブルに変換して表示
        return data.to_html()
    except FileNotFoundError:
        return "<h1>まだ分析データがありません。</h1>"

if __name__ == '__main__':
    # 外部からアクセスできるように host='0.0.0.0' を指定
    app.run(host='0.0.0.0', port=5001)