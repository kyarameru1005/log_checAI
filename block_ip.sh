#!/bin/bash

# --- 設定 ---
BLOCK_FILE="/etc/apache2/conf-available/block-list.conf"
IP_TO_BLOCK=$1

# --- スクリプト本体 ---
echo "--- IPブロック スクリプト ---"

# ① IPアドレスが指定されているかチェック
if [ -z "$IP_TO_BLOCK" ]; then
  echo "エラー: ブロックするIPアドレスを指定してください。"
  echo "使い方: sudo $0 123.45.67.89"
  exit 1
fi

# ② ブロックファイルがなければ、ひな形を作成
if [ ! -f "$BLOCK_FILE" ]; then
  echo "情報: ブロックファイルが見つかりません。新規作成します..."
  # ★★★★★ ここを修正！ ★★★★★
  # <Location />で囲み、「サイト全体に適用する」という指示を追加
  echo -e "<Location />\n<RequireAll>\n    Require all granted\n</RequireAll>\n</Location>" | sudo tee "$BLOCK_FILE" > /dev/null
fi

# ③ すでにIPがブロック済みかチェック
if grep -q "Require not ip $IP_TO_BLOCK" "$BLOCK_FILE"; then
  echo "情報: IPアドレス $IP_TO_BLOCK はすでにブロックされています。"
  exit 0
fi

# ④ バックアップを作成
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="${BLOCK_FILE}.${TIMESTAMP}"
echo "バックアップを作成中: ${BACKUP_FILE}"
sudo cp "$BLOCK_FILE" "$BACKUP_FILE"

# ⑤ sedコマンドを使い、</RequireAll>の前の行に新しいIPを追加
echo "IPアドレスをブロック中: $IP_TO_BLOCK"
sudo sed -i "/<\/RequireAll>/i \ \ \ \ Require not ip $IP_TO_BLOCK" "$BLOCK_FILE"

# ⑥ Apacheに設定ファイルを認識させる
sudo a2enconf block-list

# ⑦ Apacheを再読み込みして、設定を反映
echo "Apacheを再読み込みしています..."
# エラーが出たらスクリプトを止めるように修正
if ! sudo systemctl reload apache2; then
    echo "エラー: Apacheの再読み込みに失敗しました。設定を元に戻します。"
    sudo mv "$BACKUP_FILE" "$BLOCK_FILE" # 問題があったのでバックアップから復元
    exit 1
fi

echo "✅ 成功: IPアドレス $IP_TO_BLOCK をブロックしました。"
