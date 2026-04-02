require('dotenv').config();
const express = require('express');
const helmet  = require('helmet');
const rateLimit = require('express-rate-limit');
const fetch   = require('node-fetch');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Basic認証 ──
function basicAuth(req, res, next) {
  const user = process.env.APP_USER;
  const pass = process.env.APP_PASSWORD;
  if (!user || !pass) return next();
  const h = req.headers['authorization'];
  if (!h || !h.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="StratTask"');
    return res.status(401).send('認証が必要です');
  }
  const [u, p] = Buffer.from(h.slice(6), 'base64').toString().split(':');
  if (u !== user || p !== pass) {
    res.set('WWW-Authenticate', 'Basic realm="StratTask"');
    return res.status(401).send('IDまたはパスワードが違います');
  }
  next();
}

// ── OAuth2 アクセストークン管理 ──
// リフレッシュトークンは環境変数 GOOGLE_REFRESH_TOKEN に保存
// アクセストークンはメモリにキャッシュ（1時間有効）
let cachedAccessToken = null;
let tokenExpiry = 0;

async function getAccessToken() {
  if (cachedAccessToken && Date.now() < tokenExpiry - 60000) return cachedAccessToken;

  const clientId     = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const refreshToken = process.env.GOOGLE_REFRESH_TOKEN;

  if (!clientId || !clientSecret || !refreshToken) {
    throw new Error('Google OAuth環境変数が未設定です（GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN）');
  }

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id:     clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type:    'refresh_token'
    })
  });

  if (!res.ok) {
    const e = await res.json();
    throw new Error('トークン更新失敗: ' + (e.error_description || e.error));
  }

  const data = await res.json();
  cachedAccessToken = data.access_token;
  tokenExpiry = Date.now() + (data.expires_in || 3600) * 1000;
  return cachedAccessToken;
}

// ── Sheets API ヘルパー ──
const SHEET_ID = process.env.SPREADSHEET_ID || '10gH3TlsQOtgPnDW1AhHErpxNsBXv5kgudGJuHms5jyE';

async function sheetsGet(range) {
  const token = await getAccessToken();
  const res = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/${encodeURIComponent(range)}`,
    { headers: { Authorization: 'Bearer ' + token } }
  );
  if (!res.ok) { const e = await res.json(); throw new Error(e.error?.message || 'Sheets GET error'); }
  return res.json();
}

async function sheetsBatch(data) {
  const token = await getAccessToken();
  const res = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values:batchUpdate`,
    {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ valueInputOption: 'USER_ENTERED', data })
    }
  );
  if (!res.ok) { const e = await res.json(); throw new Error(e.error?.message || 'Sheets batch error'); }
  return res.json();
}

async function sheetsPut(range, values) {
  const token = await getAccessToken();
  const res = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/${encodeURIComponent(range)}?valueInputOption=USER_ENTERED`,
    {
      method: 'PUT',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ range, majorDimension: 'ROWS', values })
    }
  );
  if (!res.ok) { const e = await res.json(); throw new Error(e.error?.message || 'Sheets PUT error'); }
  return res.json();
}

// ── セキュリティ ──
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"],
      imgSrc:     ["'self'", "data:"]
    }
  }
}));
app.use(express.json({ limit: '1mb' }));
app.use(basicAuth);
app.use(express.static(path.join(__dirname, 'public')));

const aiLimiter     = rateLimit({ windowMs: 60000, max: 10,  message: { error: 'リクエスト頻度が高すぎます' } });
const sheetsLimiter = rateLimit({ windowMs: 60000, max: 60,  message: { error: 'リクエスト頻度が高すぎます' } });

// ── 設定情報（キー非公開） ──
app.get('/api/config', (req, res) => {
  const hasSheets = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REFRESH_TOKEN);
  res.json({
    hasAnthropicKey: !!process.env.ANTHROPIC_API_KEY,
    hasSheets,
    spreadsheetId: SHEET_ID,
    // OAuth初回設定用にクライアントIDだけ公開（secretは非公開）
    googleClientId: process.env.GOOGLE_CLIENT_ID || null
  });
});

// ── OAuth: 認証URL生成 ──
app.get('/api/oauth/url', (req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) return res.status(503).json({ error: 'GOOGLE_CLIENT_IDが未設定です' });

  const redirectUri = process.env.OAUTH_REDIRECT_URI ||
    `${req.protocol}://${req.get('host')}/api/oauth/callback`;

  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id:     clientId,
    redirect_uri:  redirectUri,
    response_type: 'code',
    scope:         'https://www.googleapis.com/auth/spreadsheets',
    access_type:   'offline',
    prompt:        'consent'   // 毎回リフレッシュトークンを返す
  });
  res.json({ url, redirectUri });
});

// ── OAuth: コールバック（コード → トークン交換） ──
app.get('/api/oauth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.send(`<h3>認証エラー: ${error}</h3>`);
  if (!code)  return res.send('<h3>認証コードがありません</h3>');

  const redirectUri = process.env.OAUTH_REDIRECT_URI ||
    `${req.protocol}://${req.get('host')}/api/oauth/callback`;

  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id:     process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri:  redirectUri,
        grant_type:    'authorization_code'
      })
    });

    if (!tokenRes.ok) {
      const e = await tokenRes.json();
      throw new Error(e.error_description || e.error);
    }

    const tokens = await tokenRes.json();
    const refreshToken = tokens.refresh_token;

    if (!refreshToken) {
      return res.send(`
        <h3 style="color:orange">アクセストークンのみ取得（リフレッシュトークンなし）</h3>
        <p>すでに認証済みの可能性があります。Google アカウントのアプリ連携を解除してから再試行してください。</p>
        <a href="/">トップに戻る</a>
      `);
    }

    // リフレッシュトークンを表示（ユーザーが環境変数に設定する）
    res.send(`<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8">
      <title>OAuth認証完了</title>
      <style>
        body{font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 20px;color:#1a1a18;}
        h2{color:#1D9E75;} code{background:#f5f5f3;padding:4px 8px;border-radius:6px;font-size:13px;word-break:break-all;display:block;margin:8px 0;}
        .box{border:1px solid #ddd;border-radius:8px;padding:16px;margin:16px 0;background:#f9f9f9;}
        .step{display:flex;gap:10px;margin:10px 0;align-items:flex-start;font-size:14px;}
        .num{background:#1D9E75;color:#fff;width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0;}
        .btn{background:#1D9E75;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;}
      </style></head><body>
      <h2>✓ Google認証完了！</h2>
      <p>リフレッシュトークンを取得しました。以下の手順でRenderに設定してください。</p>
      <div class="box">
        <b>GOOGLE_REFRESH_TOKEN の値：</b>
        <code id="rt">${refreshToken}</code>
        <button class="btn" onclick="navigator.clipboard.writeText(document.getElementById('rt').textContent);this.textContent='コピーしました！'">コピー</button>
      </div>
      <div class="box">
        <div class="step"><div class="num">1</div><div>上のトークンをコピー</div></div>
        <div class="step"><div class="num">2</div><div>Renderダッシュボード → Environment → <b>GOOGLE_REFRESH_TOKEN</b> に貼り付け</div></div>
        <div class="step"><div class="num">3</div><div>「Save Changes」→ サービスが自動再起動されます</div></div>
        <div class="step"><div class="num">4</div><div><a href="/">アプリに戻る</a> → Sheets同期タブで動作確認</div></div>
      </div>
      <p style="font-size:12px;color:#888;">このページを閉じてもトークンはRenderに保存すれば有効です。</p>
    </body></html>`);

  } catch(e) {
    res.send(`<h3>トークン取得エラー: ${e.message}</h3><a href="/">戻る</a>`);
  }
});

// ── AI タスク生成 ──
app.post('/api/generate-tasks', aiLimiter, async (req, res) => {
  if (!process.env.ANTHROPIC_API_KEY)
    return res.status(503).json({ error: 'ANTHROPIC_API_KEY が未設定です' });

  const { goal } = req.body;
  if (!goal?.content) return res.status(400).json({ error: '目標内容が必要です' });

  const today = new Date();
  const mon   = new Date(today);
  mon.setDate(today.getDate() - ((today.getDay() + 6) % 7));
  const days = Array.from({ length: 7 }, (_, i) => {
    const d = new Date(mon); d.setDate(mon.getDate() + i);
    return d.toISOString().split('T')[0];
  });
  const pLabel = { asap:'ASAP', high:'高', mid:'中', low:'低' };

  const prompt = `あなたはタスク管理の専門家です。以下の中長期目標から今週の具体的な業務タスクを作成してください。

目標: ${goal.content}
達成期間: ${goal.period || '未設定'}
担当者: ${goal.owner || '未設定'}
優先度: ${pLabel[goal.priority] || goal.priority}
備考: ${goal.note || 'なし'}
今週の日付: ${days.join(', ')}

以下のJSON配列のみを返してください（説明文・マークダウン不要）:
[{"date":"YYYY-MM-DD","time":"09-12","name":"タスク名30字以内","detail":"詳細80字以内","priority":"asap|high|mid|low"}]

今週全体で6〜10件、日付を分散させて作成してください。`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 1500, messages: [{ role: 'user', content: prompt }] })
    });
    if (!response.ok) { const e = await response.json(); throw new Error(e.error?.message); }
    const data  = await response.json();
    const text  = data.content.map(c => c.text || '').join('');
    const tasks = JSON.parse(text.replace(/```json|```/g, '').trim());
    res.json({ tasks });
  } catch(e) {
    console.error('AI error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Sheets: シート1（中長期KPI）転記 ──
app.post('/api/sheets/sync-kpi', sheetsLimiter, async (req, res) => {
  try {
    const { goals } = req.body;
    if (!goals?.length) return res.json({ updated: 0 });

    const existing  = await sheetsGet("'中長期KPI'!A2:A200");
    const existingNames = (existing.values || []).map(r => r[0]).filter(Boolean);
    const existingFull  = await sheetsGet("'中長期KPI'!A2:I200");
    let writeRow = (existingFull.values || []).length + 2;

    const updates = [];
    let written = 0;
    const pLabel = { asap:'ASAP', high:'高', mid:'中', low:'低' };

    for (const g of goals) {
      if (existingNames.includes(g.content)) continue;
      updates.push({ range: `'中長期KPI'!A${writeRow}`, values: [[g.content]] });
      updates.push({ range: `'中長期KPI'!B${writeRow}`, values: [[pLabel[g.priority] || '']] });
      updates.push({ range: `'中長期KPI'!C${writeRow}`, values: [[g.period || '']] });
      updates.push({ range: `'中長期KPI'!D${writeRow}`, values: [[g.owner || '']] });
      updates.push({ range: `'中長期KPI'!E${writeRow}`, values: [[g.note || '']] });
      const ms = (g.milestones || []).slice(0, 4);
      ms.forEach((m, j) => {
        updates.push({ range: `'中長期KPI'!G${writeRow + j}`, values: [[m.text || '']] });
        updates.push({ range: `'中長期KPI'!H${writeRow + j}`, values: [[m.done ? 'TRUE' : 'FALSE']] });
        if (m.date) updates.push({ range: `'中長期KPI'!I${writeRow + j}`, values: [[m.date]] });
      });
      writeRow += Math.max(ms.length, 1) + 1;
      written++;
    }

    if (updates.length) await sheetsBatch(updates);
    res.json({ updated: written });
  } catch(e) {
    console.error('sync-kpi error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Sheets: 日別目標設定シート転記 ──
app.post('/api/sheets/sync-tasks', sheetsLimiter, async (req, res) => {
  try {
    const { tasks } = req.body;
    if (!tasks?.length) return res.json({ updated: 0 });
    const pLabel = { asap:'ASAP', high:'高', mid:'中', low:'低' };

    const existing = await sheetsGet("'日別目標設定'!A2:G200");
    const rows = existing.values || [];
    const emptyRows = [];
    for (let i = 0; i < 200; i++) {
      if (!rows[i] || !rows[i][0]) emptyRows.push(i + 2);
    }

    // 優先度順にソート
    const sorted = [...tasks].sort((a, b) => {
      const o = { asap:0, high:1, mid:2, low:3 };
      return (o[a.priority] ?? 4) - (o[b.priority] ?? 4);
    });

    const updates = [];
    let idx = 0;
    for (const t of sorted) {
      if (idx >= emptyRows.length) break;
      const row = emptyRows[idx++];
      updates.push({ range: `'日別目標設定'!A${row}`, values: [[t.date]] });
      updates.push({ range: `'日別目標設定'!B${row}`, values: [[t.time]] });
      updates.push({ range: `'日別目標設定'!C${row}`, values: [[t.name]] });
      updates.push({ range: `'日別目標設定'!D${row}`, values: [[t.detail || '']] });
      updates.push({ range: `'日別目標設定'!E${row}`, values: [[pLabel[t.priority] || '']] });
      updates.push({ range: `'日別目標設定'!F${row}`, values: [[t.done ? 'TRUE' : 'FALSE']] });
      if (t.note) updates.push({ range: `'日別目標設定'!G${row}`, values: [[t.note]] });
    }

    if (updates.length) await sheetsBatch(updates);
    res.json({ updated: idx });
  } catch(e) {
    console.error('sync-tasks error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Sheets: タスクチェック更新 ──
app.post('/api/sheets/update-check', sheetsLimiter, async (req, res) => {
  try {
    const { taskName, done } = req.body;
    if (!taskName) return res.status(400).json({ error: 'taskNameが必要です' });
    const data = await sheetsGet("'日別目標設定'!C2:F200");
    const rows = data.values || [];
    const updates = [];
    for (let i = 0; i < rows.length; i++) {
      if ((rows[i][0] || '').includes(taskName))
        updates.push({ range: `'日別目標設定'!F${i + 2}`, values: [[done ? 'TRUE' : 'FALSE']] });
    }
    if (updates.length) await sheetsBatch(updates);
    res.json({ updated: updates.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Sheets: マイルストーンチェック更新 ──
app.post('/api/sheets/update-milestone', sheetsLimiter, async (req, res) => {
  try {
    const { milestoneText, done } = req.body;
    if (!milestoneText) return res.status(400).json({ error: 'milestoneTextが必要です' });
    const data = await sheetsGet("'中長期KPI'!G2:H200");
    const rows = data.values || [];
    const updates = [];
    for (let i = 0; i < rows.length; i++) {
      if ((rows[i][0] || '') === milestoneText)
        updates.push({ range: `'中長期KPI'!H${i + 2}`, values: [[done ? 'TRUE' : 'FALSE']] });
    }
    if (updates.length) await sheetsBatch(updates);
    res.json({ updated: updates.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Sheets: KPI進捗率更新 ──
app.post('/api/sheets/update-progress', sheetsLimiter, async (req, res) => {
  try {
    const { goalName, progress } = req.body;
    const data = await sheetsGet("'中長期KPI'!A2:F200");
    const rows = data.values || [];
    const updates = [];
    for (let i = 0; i < rows.length; i++) {
      if ((rows[i][0] || '') === goalName) {
        updates.push({ range: `'中長期KPI'!F${i + 2}`, values: [[progress + '%']] });
        break;
      }
    }
    if (updates.length) await sheetsBatch(updates);
    res.json({ updated: updates.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SPA フォールバック ──
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`StratTask server running on port ${PORT}`);
  const hasSheets = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REFRESH_TOKEN);
  if (!process.env.ANTHROPIC_API_KEY) console.warn('⚠ ANTHROPIC_API_KEY 未設定');
  if (!hasSheets) console.warn('⚠ Google OAuth未設定（GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN）');
  else console.log('✓ Google Sheets OAuth設定済み');
  if (!process.env.APP_USER) console.warn('⚠ Basic認証未設定（認証なしで動作）');
  else console.log('✓ Basic認証有効');
});
