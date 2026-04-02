# StratTask

中長期目標と週次タスクを管理し、Google Sheetsに自動転記するタスク管理アプリ。

## 機能

- 中長期目標の入力・管理（優先度・サブタスク・マイルストーン）
- AIによる週次タスク自動生成（Anthropic Claude）
- Google Sheetsへの自動転記
  - シート1：年間目標管理シート（プロジェクト名・サブタスク）
  - 月別シート：日付・時間帯・タスク名・優先度・チェック・備考
- タスクチェック → 中長期目標の進捗に連動

## セキュリティ

- APIキーはサーバー側の環境変数にのみ保存（クライアントに非公開）
- Google OAuthトークンはクライアントで管理（サーバーに保存しない）
- Sheetsへの書き込みはサーバープロキシ経由

## Renderへのデプロイ

### 1. GitHubにプッシュ

```bash
git init
git add .
git commit -m "initial commit"
git remote add origin https://github.com/yourname/strattask.git
git push -u origin main
```

### 2. Render設定

1. [Render.com](https://render.com/) で「New Web Service」
2. GitHubリポジトリを接続
3. 以下を設定：
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Node Version**: 18以上

### 3. 環境変数（Renderのダッシュボードで設定）

| 変数名 | 説明 |
|--------|------|
| `ANTHROPIC_API_KEY` | AnthropicのAPIキー |
| `GOOGLE_CLIENT_ID` | Google OAuthクライアントID |
| `SPREADSHEET_ID` | 転記先スプレッドシートID |
| `SHEET1_NAME` | シート1のタブ名（例: シート1） |
| `SHEET_PREFIX` | 月別シートのプレフィックス（例: 2026/） |
| `NODE_ENV` | production |

### 4. Google Cloud Console設定

1. [Google Cloud Console](https://console.cloud.google.com/) でプロジェクト作成
2. Google Sheets API を有効化
3. 「認証情報」→「OAuthクライアントID」作成（種類：ウェブアプリ）
4. **承認済みJavaScriptオリジン**に Renderのデプロイ先URL を追加
   - 例: `https://strattask.onrender.com`
5. クライアントIDを `GOOGLE_CLIENT_ID` 環境変数に設定

## ローカル開発

```bash
# 依存関係インストール
npm install

# 環境変数設定
cp .env.example .env
# .env を編集して各APIキーを入力

# 起動
npm run dev
# → http://localhost:3000
```

## ファイル構成

```
strattask/
├── server.js          # Express サーバー（APIプロキシ）
├── public/
│   └── index.html     # フロントエンド（SPA）
├── package.json
├── .env.example       # 環境変数のテンプレート
├── .gitignore         # .env を除外
└── README.md
```
