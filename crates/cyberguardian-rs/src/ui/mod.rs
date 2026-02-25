pub async fn index() -> axum::response::Html<&'static str> {
    axum::response::Html(
        r#"
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>CyberGuardian-RS</title>
  <style>
    :root {
      --bg: #0b1220;
      --card: #131d33;
      --line: #263551;
      --text: #e5ecff;
      --muted: #9eb0d6;
      --accent: #5cc8ff;
      --ok: #41d38a;
      --warn: #f7b955;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, Segoe UI, Roboto, sans-serif;
      background: radial-gradient(circle at 15% -10%, #1f3566, var(--bg));
      color: var(--text);
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
    .header { display: flex; justify-content: space-between; align-items: center; gap: 16px; }
    .title { margin: 0; font-size: 1.9rem; }
    .subtitle { margin: 8px 0 0; color: var(--muted); }
    .badge { padding: 6px 10px; border-radius: 999px; border: 1px solid var(--line); background: #0f1729; }
    .grid { display: grid; gap: 16px; margin-top: 20px; }
    .grid.cards { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
    .card {
      background: color-mix(in oklab, var(--card) 94%, black);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 16px;
      box-shadow: 0 10px 35px rgba(0,0,0,.18);
    }
    .metric { font-size: 2rem; margin: 8px 0; color: var(--accent); }
    .row { display: grid; grid-template-columns: 320px 1fr; gap: 16px; margin-top: 16px; }
    label { display: block; margin: 10px 0 6px; color: var(--muted); font-size: .9rem; }
    input, select, button {
      width: 100%; border-radius: 10px; border: 1px solid var(--line); background: #0d1629;
      color: var(--text); padding: 10px 12px;
    }
    button { background: linear-gradient(90deg, #1b7cff, #2ca0ff); border: none; font-weight: 600; cursor: pointer; }
    button.secondary { background: #1b2740; border: 1px solid var(--line); }
    .status { margin-top: 10px; color: var(--muted); font-size: .9rem; min-height: 22px; }
    .tables { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); margin-top: 16px; }
    table { width: 100%; border-collapse: collapse; font-size: .9rem; }
    th, td { padding: 8px 10px; border-bottom: 1px solid var(--line); text-align: left; }
    th { color: var(--muted); font-weight: 600; }
    .pill { border-radius: 999px; padding: 2px 9px; font-size: .78rem; border: 1px solid var(--line); }
    .pill.done { color: var(--ok); }
    .pill.running { color: var(--warn); }
    @media (max-width: 980px) { .row { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <main class="container">
    <header class="header card">
      <div>
        <h1 class="title">CyberGuardian-RS</h1>
        <p class="subtitle">Dashboard local pour audit autorisé (scope contrôlé, jobs, assets, findings).</p>
      </div>
      <span class="badge" id="roleBadge">non connecté</span>
    </header>

    <section class="grid cards">
      <article class="card"><div>Jobs</div><div class="metric" id="jobsCount">0</div></article>
      <article class="card"><div>Assets</div><div class="metric" id="assetsCount">0</div></article>
      <article class="card"><div>Findings</div><div class="metric" id="findingsCount">0</div></article>
    </section>

    <section class="row">
      <aside class="card">
        <h3>Authentification</h3>
        <label>Utilisateur</label><input id="username" value="operator"/>
        <label>Mot de passe</label><input id="password" type="password" value="operator123"/>
        <button id="loginBtn">Se connecter</button>

        <h3 style="margin-top:22px">Lancer un job</h3>
        <label>Cible (dans le scope)</label><input id="target" value="127.0.0.1"/>
        <label>Outil</label><select id="tool"><option>nmap</option></select>
        <label>Profil</label><select id="profile"><option>safe</option><option>balanced</option></select>
        <button id="createBtn">Créer le job</button>
        <button class="secondary" id="refreshBtn" style="margin-top:8px">Rafraîchir</button>
        <div class="status" id="status">Connectez-vous pour charger les données.</div>
      </aside>

      <section>
        <div class="tables">
          <article class="card">
            <h3>Jobs récents</h3>
            <table><thead><tr><th>ID</th><th>Target</th><th>Status</th></tr></thead><tbody id="jobsBody"></tbody></table>
          </article>
          <article class="card">
            <h3>Assets</h3>
            <table><thead><tr><th>ID</th><th>IP</th><th>Hostname</th></tr></thead><tbody id="assetsBody"></tbody></table>
          </article>
          <article class="card">
            <h3>Findings</h3>
            <table><thead><tr><th>ID</th><th>Key</th><th>Sévérité</th></tr></thead><tbody id="findingsBody"></tbody></table>
          </article>
        </div>
      </section>
    </section>
  </main>

<script>
let token = "";
const roleBadge = document.getElementById('roleBadge');
const statusEl = document.getElementById('status');

const api = async (url, opts = {}) => {
  const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  if (token) headers.Authorization = `Bearer ${token}`;
  const resp = await fetch(url, Object.assign({}, opts, { headers }));
  if (!resp.ok) throw new Error(await resp.text());
  return resp.json();
};

const setRows = (elId, rows, cols) => {
  const body = document.getElementById(elId);
  body.innerHTML = rows.map((r) => `<tr>${cols.map((c) => `<td>${c(r)}</td>`).join('')}</tr>`).join('') || '<tr><td colspan="3">Aucune donnée</td></tr>';
};

async function refreshAll() {
  const [jobs, assets, findings] = await Promise.all([
    api('/api/jobs'),
    api('/api/assets'),
    api('/api/findings'),
  ]);

  document.getElementById('jobsCount').textContent = jobs.length;
  document.getElementById('assetsCount').textContent = assets.length;
  document.getElementById('findingsCount').textContent = findings.length;

  setRows('jobsBody', jobs.slice(0, 8), [
    (r) => r.id,
    (r) => r.target,
    (r) => `<span class="pill ${r.status}">${r.status}</span>`,
  ]);
  setRows('assetsBody', assets.slice(0, 8), [
    (r) => r.id,
    (r) => r.ip,
    (r) => r.hostname || '-',
  ]);
  setRows('findingsBody', findings.slice(0, 8), [
    (r) => r.id,
    (r) => r.key,
    (r) => r.severity,
  ]);

  statusEl.textContent = `Dernière MAJ: ${new Date().toLocaleTimeString()}`;
}

document.getElementById('loginBtn').onclick = async () => {
  try {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    const data = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
    token = data.token;
    roleBadge.textContent = `connecté: ${data.role}`;
    await refreshAll();
  } catch (e) {
    statusEl.textContent = `Erreur login: ${e.message}`;
  }
};

document.getElementById('createBtn').onclick = async () => {
  try {
    await api('/api/jobs', {
      method: 'POST',
      body: JSON.stringify({
        target: document.getElementById('target').value.trim(),
        tool: document.getElementById('tool').value,
        profile: document.getElementById('profile').value,
      })
    });
    statusEl.textContent = 'Job créé.';
    setTimeout(refreshAll, 300);
  } catch (e) {
    statusEl.textContent = `Erreur job: ${e.message}`;
  }
};

document.getElementById('refreshBtn').onclick = () => refreshAll().catch(e => statusEl.textContent = `Erreur refresh: ${e.message}`);
</script>
</body>
</html>
"#,
    )
}
