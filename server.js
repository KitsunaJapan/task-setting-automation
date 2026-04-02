require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Basic認証 ──
function basicAuth(req, res, next) {
  const user = process.env.APP_USER;
  const pass = process.env.APP_PASSWORD;
  if (!user || !pass) return next();
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="StratTask"');
    return res.status(401).send('認証が必要です');
  }
  const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf-8');
  const [u, p] = decoded.split(':');
  if (u !== user || p !== pass) {
    res.set('WWW-Authenticate', 'Basic realm="StratTask"');
    return res.status(401).send('IDまたはパスワードが違います');
  }
  next();
}

// ── Google サービスアカウント JWT → アクセストークン ──
let cachedToken = null;
let tokenExpiry = 0;

async function getGoogleToken() {
  if (cachedToken && Date.now() < tokenExpiry - 60000) return cachedToken;

  const credJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  if (!credJson) throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON が未設定です');

  const cred = JSON.parse(credJson);
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: cred.client_email,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600
  };

  const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const signingInput = `${b64(header)}.${b64(payload)}`;

  // Node.js crypto で RS256 署名
  const crypto = require('crypto');
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(signingInput);
  const signature = sign.sign(cred.private_key, 'base64url');
  const jwt = `${signingInput}.${signature}`;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`
  });
  if (!res.ok) {
    const e = await res.json();
    throw new Error('Google token error: ' + (e.error_description || e.error));
  }
  const data = await res.json();
  cachedToken = data.access_token;
  tokenExpiry = Date.now() + data.expires_in * 1000;
  return cachedToken;
}

// ── Sheets API ヘルパー ──
const SHEET_ID = process.env.SPREADSHEET_ID || '10gH3TlsQOtgPnDW1AhHErpxNsBXv5kgudGJuHms5jyE';

async function sheetsGet(range) {
  const token = await getGoogleToken();
  const res = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/${encodeURIComponent(range)}`,
    { headers: { Authorization: 'Bearer ' + token } }
  );
  if (!res.ok) { const e = await res.json(); throw new Error(e.error?.message || 'Sheets GET error'); }
  return res.json();
}

async function sheetsBatch(data) {
  const token = await getGoogleToken();
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
  const token = await getGoogleToken();
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

const aiLimiter = rateLimit({ windowMs: 60000, max: 10, message: { error: 'リクエスト頻度が高すぎます' } });
const sheetsLimiter = rateLimit({ windowMs: 60000, max: 60, message: { error: 'リクエスト頻度が高すぎます' } });

// ── 設定情報 ──
app.get('/api/config', (req, res) => {
  res.json({
    hasAnthropicKey: !!process.env.ANTHROPIC_API_KEY,
    hasSheets: !!process.env.GOOGLE_SERVICE_ACCOUNT_JSON,
    spreadsheetId: SHEET_ID
  });
});

// ── AI タスク生成 ──
app.post('/api/generate-tasks', aiLimiter, async (req, res) => {
  if (!process.env.ANTHROPIC_API_KEY)
    return res.status(503).json({ error: 'ANTHROPIC_API_KEY が未設定です' });

  const { goal } = req.body;
  if (!goal?.content) return res.status(400).json({ error: '目標内容が必要です' });

  const today = new Date();
  const mon = new Date(today);
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
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 1500, messages: [{ role: 'user', content: prompt }] })
    });
    if (!response.ok) { const e = await response.json(); throw new Error(e.error?.message); }
    const data = await response.json();
    const text = data.content.map(c => c.text || '').join('');
    const tasks = JSON.parse(text.replace(/```json|```/g, '').trim());
    res.json({ tasks });
  } catch (e) {
    console.error('AI error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Sheets: シート1（中長期KPI）へ転記 ──
app.post('/api/sheets/sync-kpi', sheetsLimiter, async (req, res) => {
  try {
    const { goals } = req.body;
    if (!goals?.length) return res.json({ updated: 0 });

    // 既存データ取得（A列のプロジェクト名）
    const existing = await sheetsGet("'中長期KPI'!A2:A200");
    const existingNames = (existing.values || []).map(r => r[0]).filter(Boolean);

    // 書き込み済みの行数を把握
    const existingFull = await sheetsGet("'中長期KPI'!A2:D200");
    const existingRows = existingFull.values || [];
    let writeRow = existingRows.length + 2;

    const updates = [];
    let written = 0;

    for (const g of goals) {
      if (existingNames.includes(g.content)) continue;

      // A列: プロジェクト名
      updates.push({ range: `'中長期KPI'!A${writeRow}`, values: [[g.content]] });
      // B列: 優先度
      updates.push({ range: `'中長期KPI'!B${writeRow}`, values: [[{ asap:'ASAP', high:'高', mid:'中', low:'低' }[g.priority] || '']] });
      // C列: 達成期間
      updates.push({ range: `'中長期KPI'!C${writeRow}`, values: [[g.period || '']] });
      // D列: 担当者
      updates.push({ range: `'中長期KPI'!D${writeRow}`, values: [[g.owner || '']] });
      // E列: 備考
      updates.push({ range: `'中長期KPI'!E${writeRow}`, values: [[g.note || '']] });

      // マイルストーン（F列以降に横並び、またはG列に縦並び）
      const ms = (g.milestones || []).slice(0, 4);
      ms.forEach((m, i) => {
        updates.push({ range: `'中長期KPI'!G${writeRow + i}`, values: [[m.text || '']] });
        updates.push({ range: `'中長期KPI'!H${writeRow + i}`, values: [[m.done ? 'TRUE' : 'FALSE']] });
        if (m.date) updates.push({ range: `'中長期KPI'!I${writeRow + i}`, values: [[m.date]] });
      });

      writeRow += Math.max(ms.length, 1) + 1;
      written++;
    }

    if (updates.length) await sheetsBatch(updates);
    res.json({ updated: written });
  } catch (e) {
    console.error('sync-kpi error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Sheets: シート2（日別目標）へ転記 ──
app.post('/api/sheets/sync-tasks', sheetsLimiter, async (req, res) => {
  try {
    const { tasks } = req.body;
    if (!tasks?.length) return res.json({ updated: 0 });

    const pLabel = { asap:'ASAP', high:'高', mid:'中', low:'低' };

    // タスクを月ごとにグループ化
    const byMonth = {};
    for (const t of tasks) {
      if (!t.date) continue;
      const d = new Date(t.date);
      const mm = String(d.getMonth() + 1).padStart(2, '0');
      const key = `日別目標_${d.getFullYear()}${mm}`;
      if (!byMonth[key]) byMonth[key] = [];
      byMonth[key].push(t);
    }

    const updates = [];
    let totalWritten = 0;

    for (const [sheetName, monthTasks] of Object.entries(byMonth)) {
      // B列（時間帯）を取得して空き行を確認
      let existing;
      try { existing = await sheetsGet(`'日別目標設定'!A2:F200`); }
      catch(e) {
        // シートが見つからない場合は「日別目標設定」シートにまとめて書く
        existing = { values: [] };
      }

      const rows = existing.values || [];
      // A列が空の行番号を探す（1-indexed、2行目スタート）
      const emptyRows = [];
      for (let i = 0; i < 200; i++) {
        if (!rows[i] || !rows[i][0]) emptyRows.push(i + 2);
      }

      // 優先度順にソート
      const sorted = [...monthTasks].sort((a, b) => {
        const o = { asap:0, high:1, mid:2, low:3 };
        return (o[a.priority] ?? 4) - (o[b.priority] ?? 4);
      });

      let idx = 0;
      for (const t of sorted) {
        if (idx >= emptyRows.length) break;
        const row = emptyRows[idx++];
        const d = new Date(t.date);
        updates.push({ range: `'日別目標設定'!A${row}`, values: [[t.date]] });
        updates.push({ range: `'日別目標設定'!B${row}`, values: [[t.time]] });
        updates.push({ range: `'日別目標設定'!C${row}`, values: [[t.name]] });
        updates.push({ range: `'日別目標設定'!D${row}`, values: [[t.detail || '']] });
        updates.push({ range: `'日別目標設定'!E${row}`, values: [[pLabel[t.priority] || '']] });
        updates.push({ range: `'日別目標設定'!F${row}`, values: [[t.done ? 'TRUE' : 'FALSE']] });
        if (t.note) updates.push({ range: `'日別目標設定'!G${row}`, values: [[t.note]] });
        totalWritten++;
      }
    }

    if (updates.length) await sheetsBatch(updates);
    res.json({ updated: totalWritten });
  } catch (e) {
    console.error('sync-tasks error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Sheets: チェック状態を更新（タスク単体） ──
app.post('/api/sheets/update-check', sheetsLimiter, async (req, res) => {
  try {
    const { taskName, done } = req.body;
    if (!taskName) return res.status(400).json({ error: 'taskName が必要です' });

    const data = await sheetsGet("'日別目標設定'!C2:F200");
    const rows = data.values || [];
    const updates = [];

    for (let i = 0; i < rows.length; i++) {
      if ((rows[i][0] || '').includes(taskName)) {
        updates.push({ range: `'日別目標設定'!F${i + 2}`, values: [[done ? 'TRUE' : 'FALSE']] });
      }
    }

    if (updates.length) await sheetsBatch(updates);
    res.json({ updated: updates.length });
  } catch (e) {
    console.error('update-check error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Sheets: マイルストーンチェック更新 ──
app.post('/api/sheets/update-milestone', sheetsLimiter, async (req, res) => {
  try {
    const { goalName, milestoneText, done } = req.body;
    if (!milestoneText) return res.status(400).json({ error: 'milestoneText が必要です' });

    const data = await sheetsGet("'中長期KPI'!G2:H200");
    const rows = data.values || [];
    const updates = [];

    for (let i = 0; i < rows.length; i++) {
      if ((rows[i][0] || '') === milestoneText) {
        updates.push({ range: `'中長期KPI'!H${i + 2}`, values: [[done ? 'TRUE' : 'FALSE']] });
      }
    }

    if (updates.length) await sheetsBatch(updates);
    res.json({ updated: updates.length });
  } catch (e) {
    console.error('update-milestone error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Sheets: KPI進捗率を更新 ──
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
  } catch (e) {
    console.error('update-progress error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── SPA フォールバック ──
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`StratTask server running on port ${PORT}`);
  if (!process.env.ANTHROPIC_API_KEY) console.warn('⚠ ANTHROPIC_API_KEY 未設定');
  if (!process.env.GOOGLE_SERVICE_ACCOUNT_JSON) console.warn('⚠ GOOGLE_SERVICE_ACCOUNT_JSON 未設定');
  else console.log('✓ Google Sheets サービスアカウント設定済み');
  if (!process.env.APP_USER) console.warn('⚠ Basic認証未設定（認証なしで動作）');
  else console.log('✓ Basic認証有効');
});
