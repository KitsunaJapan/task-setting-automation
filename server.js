require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ── セキュリティ設定 ──
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com",
        "https://apis.google.com",
        "https://accounts.google.com"
      ],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: [
        "'self'",
        "https://sheets.googleapis.com",
        "https://accounts.google.com",
        "https://oauth2.googleapis.com"
      ],
      frameSrc: ["https://accounts.google.com"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── レート制限 ──
const aiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1分
  max: 10,
  message: { error: 'リクエスト頻度が高すぎます。しばらくお待ちください。' }
});

const sheetsLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'リクエスト頻度が高すぎます。しばらくお待ちください。' }
});

// ── 環境変数チェック ──
function checkEnv() {
  const missing = [];
  if (!process.env.ANTHROPIC_API_KEY) missing.push('ANTHROPIC_API_KEY');
  if (!process.env.GOOGLE_CLIENT_ID) missing.push('GOOGLE_CLIENT_ID');
  if (!process.env.SPREADSHEET_ID) missing.push('SPREADSHEET_ID');
  return missing;
}

// ── ヘルスチェック & 設定情報（キー非公開） ──
app.get('/api/config', (req, res) => {
  const missing = checkEnv();
  res.json({
    googleClientId: process.env.GOOGLE_CLIENT_ID || null,
    spreadsheetId: process.env.SPREADSHEET_ID || null,
    sheet1Name: process.env.SHEET1_NAME || 'シート1',
    sheetPrefix: process.env.SHEET_PREFIX || '2026/',
    hasAnthropicKey: !!process.env.ANTHROPIC_API_KEY,
    missingEnvVars: missing,
    ready: missing.length === 0
  });
});

// ── Anthropic APIプロキシ（AIタスク生成） ──
app.post('/api/generate-tasks', aiLimiter, async (req, res) => {
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(503).json({ error: 'ANTHROPIC_API_KEY が設定されていません' });
  }

  const { goal } = req.body;
  if (!goal || !goal.content) {
    return res.status(400).json({ error: '目標内容が必要です' });
  }

  const today = new Date();
  const mon = new Date(today);
  mon.setDate(today.getDate() - ((today.getDay() + 6) % 7));
  const days = Array.from({ length: 7 }, (_, i) => {
    const d = new Date(mon);
    d.setDate(mon.getDate() + i);
    return d.toISOString().split('T')[0];
  });

  const pLabel = { asap: 'ASAP', high: '高', mid: '中', low: '低' };

  const prompt = `あなたはタスク管理の専門家です。以下の中長期目標から今週の具体的な業務タスクを作成してください。

目標: ${goal.content}
達成期間: ${goal.period || '未設定'}
担当者: ${goal.owner || '未設定'}
優先度: ${pLabel[goal.priority] || goal.priority}
備考: ${goal.note || 'なし'}
今週の日付: ${days.join(', ')}

以下のJSON配列のみを返してください（説明文・マークダウン記法不要）:
[{"date":"YYYY-MM-DD","time":"09-12","name":"タスク名30字以内","detail":"詳細80字以内","priority":"asap|high|mid|low"}]

今週全体で6〜10件、日付を分散させて作成してください。`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1500,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error?.message || `Anthropic API error ${response.status}`);
    }

    const data = await response.json();
    const text = data.content.map(c => c.text || '').join('');
    const clean = text.replace(/```json|```/g, '').trim();
    const tasks = JSON.parse(clean);

    res.json({ tasks });
  } catch (e) {
    console.error('AI generate error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Google Sheets プロキシ（アクセストークンはクライアントから受け取る） ──
// ※ トークンはユーザー自身のGoogle OAuthトークン。サーバーには保存しない。
app.post('/api/sheets/get', sheetsLimiter, async (req, res) => {
  const { token, spreadsheetId, range } = req.body;
  if (!token || !range) return res.status(400).json({ error: 'token と range が必要です' });

  const sid = spreadsheetId || process.env.SPREADSHEET_ID;
  if (!sid) return res.status(400).json({ error: 'SPREADSHEET_ID が未設定です' });

  try {
    const response = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sid}/values/${encodeURIComponent(range)}`,
      { headers: { 'Authorization': 'Bearer ' + token } }
    );
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error?.message || `Sheets GET error ${response.status}`);
    }
    const data = await response.json();
    res.json(data);
  } catch (e) {
    console.error('Sheets GET error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/sheets/batch-update', sheetsLimiter, async (req, res) => {
  const { token, spreadsheetId, data } = req.body;
  if (!token || !data) return res.status(400).json({ error: 'token と data が必要です' });

  const sid = spreadsheetId || process.env.SPREADSHEET_ID;
  if (!sid) return res.status(400).json({ error: 'SPREADSHEET_ID が未設定です' });

  try {
    const response = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sid}/values:batchUpdate`,
      {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          valueInputOption: 'USER_ENTERED',
          data
        })
      }
    );
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error?.message || `Sheets batchUpdate error ${response.status}`);
    }
    const result = await response.json();
    res.json(result);
  } catch (e) {
    console.error('Sheets batchUpdate error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/sheets/put', sheetsLimiter, async (req, res) => {
  const { token, spreadsheetId, range, values } = req.body;
  if (!token || !range || !values) return res.status(400).json({ error: 'token, range, values が必要です' });

  const sid = spreadsheetId || process.env.SPREADSHEET_ID;
  if (!sid) return res.status(400).json({ error: 'SPREADSHEET_ID が未設定です' });

  try {
    const response = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sid}/values/${encodeURIComponent(range)}?valueInputOption=USER_ENTERED`,
      {
        method: 'PUT',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ range, majorDimension: 'ROWS', values })
      }
    );
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error?.message || `Sheets PUT error ${response.status}`);
    }
    const result = await response.json();
    res.json(result);
  } catch (e) {
    console.error('Sheets PUT error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── SPA フォールバック ──
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`StratTask server running on port ${PORT}`);
  const missing = checkEnv();
  if (missing.length > 0) {
    console.warn('⚠ 未設定の環境変数:', missing.join(', '));
  } else {
    console.log('✓ 全ての環境変数が設定されています');
  }
});
