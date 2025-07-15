# ベースとなる公式イメージを指定
FROM httpd:latest

# --- ここからがカスタマイズ ---
# メンテナンスのため、一時的に管理者(root)ユーザーに切り替える
USER root

# パッケージリストを更新し、curlをインストールする
# -y は全ての問い合わせに「yes」と答えるオプション
RUN apt-get update && apt-get install -y curl