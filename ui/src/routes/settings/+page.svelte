<!-- Settings — CyberFence Endpoint Protection -->
<script lang="ts">
  let realtimeMonitoring = true;
  let scanningEnabled    = true;
  let scanArchives       = true;
  let quarantineEnabled  = true;
  let autoUpdate         = true;
  let logLevel           = 'INFO';
  let maxFileSizeMb      = 256;
  let debounceMs         = 250;
  let saved              = false;
  let saving             = false;

  function save() {
    saving = true;
    setTimeout(() => {
      saving = false;
      saved  = true;
      setTimeout(() => saved = false, 2500);
    }, 600);
  }
</script>

<div class="page animate-in">

  <!-- ── Header ─────────────────────────────────────────────────────────── -->
  <div class="page-header">
    <div>
      <h1 class="page-title">Settings</h1>
      <p class="page-sub">Configure CyberFence Endpoint Protection</p>
    </div>
    <button class="btn btn-primary" on:click={save} disabled={saving}>
      {#if saving}
        <span class="spinner-xs"></span> Saving…
      {:else if saved}
        <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>
        Saved
      {:else}
        Save Changes
      {/if}
    </button>
  </div>

  <!-- ── Protection section ─────────────────────────────────────────────── -->
  <div class="settings-section">
    <h2 class="section-title">Protection</h2>
    <div class="card settings-card">

      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Real-time monitoring</span>
          <span class="setting-desc">Watch Downloads, Desktop, and Documents folders for new files</span>
        </div>
        <label class="toggle">
          <input type="checkbox" bind:checked={realtimeMonitoring} />
          <span class="toggle-track"></span>
        </label>
      </div>

      <div class="setting-divider"></div>

      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Malware scanning</span>
          <span class="setting-desc">Scan files with the CyberFence Engine on access</span>
        </div>
        <label class="toggle">
          <input type="checkbox" bind:checked={scanningEnabled} />
          <span class="toggle-track"></span>
        </label>
      </div>

      <div class="setting-divider"></div>

      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Auto-quarantine threats</span>
          <span class="setting-desc">Automatically move infected files to the secure quarantine vault</span>
        </div>
        <label class="toggle">
          <input type="checkbox" bind:checked={quarantineEnabled} />
          <span class="toggle-track"></span>
        </label>
      </div>

    </div>
  </div>

  <!-- ── Scanner section ─────────────────────────────────────────────────── -->
  <div class="settings-section">
    <h2 class="section-title">Scanner</h2>
    <div class="card settings-card">

      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Scan archives</span>
          <span class="setting-desc">Inspect .zip, .tar, .gz, .rar, and 7z archives for embedded threats</span>
        </div>
        <label class="toggle">
          <input type="checkbox" bind:checked={scanArchives} />
          <span class="toggle-track"></span>
        </label>
      </div>

      <div class="setting-divider"></div>

      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Max file size</span>
          <span class="setting-desc">Files larger than this limit are skipped to preserve performance</span>
        </div>
        <div class="setting-control">
          <input class="number-input" type="number" bind:value={maxFileSizeMb} min="10" max="2048" step="10" />
          <span class="setting-unit">MB</span>
        </div>
      </div>

      <div class="setting-divider"></div>

      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Event debounce window</span>
          <span class="setting-desc">Milliseconds to wait after a file change before scanning (prevents duplicate scans)</span>
        </div>
        <div class="setting-control">
          <input class="number-input" type="number" bind:value={debounceMs} min="50" max="2000" step="50" />
          <span class="setting-unit">ms</span>
        </div>
      </div>

    </div>
  </div>

  <!-- ── Updates section ─────────────────────────────────────────────────── -->
  <div class="settings-section">
    <h2 class="section-title">Definitions &amp; Updates</h2>
    <div class="card settings-card">

      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Automatic definition updates</span>
          <span class="setting-desc">Keep the CyberFence Engine virus database current (recommended)</span>
        </div>
        <label class="toggle">
          <input type="checkbox" bind:checked={autoUpdate} />
          <span class="toggle-track"></span>
        </label>
      </div>

      <div class="setting-divider"></div>

      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Update now</span>
          <span class="setting-desc">Manually pull the latest definitions from database.clamav.net</span>
        </div>
        <button class="btn btn-outline btn-sm">Update Definitions</button>
      </div>

    </div>
  </div>

  <!-- ── Logging section ─────────────────────────────────────────────────── -->
  <div class="settings-section">
    <h2 class="section-title">Diagnostics</h2>
    <div class="card settings-card">
      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Log verbosity</span>
          <span class="setting-desc">Amount of detail written to the agent log file</span>
        </div>
        <select class="select-input" bind:value={logLevel}>
          <option>ERROR</option>
          <option>WARN</option>
          <option>INFO</option>
          <option>DEBUG</option>
          <option>TRACE</option>
        </select>
      </div>
    </div>
  </div>

  <!-- ── About section ──────────────────────────────────────────────────── -->
  <div class="settings-section">
    <h2 class="section-title">About</h2>
    <div class="card about-card">
      <img src="/assets/app-icon.jpg" alt="CyberFence" class="about-icon" />
      <div class="about-info">
        <div class="about-name">CyberFence Endpoint Protection</div>
        <div class="about-meta">
          <span class="badge badge-green-sm">v0.1.0</span>
          <span class="text-faint text-xs">Phase 2 — Real-Time Scanner</span>
        </div>
        <div class="about-engine text-xs text-faint" style="margin-top:4px;">
          CyberFence Engine (ClamAV 1.4.4 LTS) · Windows x64
        </div>
        <div class="about-copy text-faint text-xs" style="margin-top:6px;">
          © 2026 Perez Technology Group, LLC · <a href="https://cyberfenceplatform.com" class="about-link" target="_blank">cyberfenceplatform.com</a>
        </div>
      </div>
    </div>
  </div>

</div>

<style>
.page { padding: 28px 32px; max-height: 100vh; overflow-y: auto; }
.page-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 24px; }
.page-title  { font-size: 22px; font-weight: 700; margin-bottom: 3px; }
.page-sub    { font-size: 13px; color: var(--text-2); font-weight: 300; }

.settings-section { margin-bottom: 20px; }
.section-title {
  font-size: 11px; font-weight: 700; color: var(--text-3);
  text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 8px;
  padding-left: 2px;
}
.settings-card { padding: 0; overflow: hidden; }

.setting-row {
  display: flex; align-items: center; gap: 16px;
  padding: 15px 18px;
}
.setting-divider { height: 1px; background: var(--border); }
.setting-info  { flex: 1; }
.setting-label { display: block; font-size: 13px; font-weight: 600; color: var(--text); margin-bottom: 2px; }
.setting-desc  { font-size: 11px; color: var(--text-3); font-weight: 400; line-height: 1.4; }

/* Toggle */
.toggle { position: relative; cursor: pointer; }
.toggle input { display: none; }
.toggle-track {
  display: block; width: 40px; height: 22px;
  background: var(--border-2); border-radius: 999px;
  position: relative; transition: background 0.2s;
}
.toggle-track::after {
  content: ''; position: absolute; top: 3px; left: 3px;
  width: 16px; height: 16px; background: white; border-radius: 50%;
  transition: transform 0.2s; box-shadow: 0 1px 3px rgba(0,0,0,0.15);
}
.toggle input:checked ~ .toggle-track { background: var(--green); }
.toggle input:checked ~ .toggle-track::after { transform: translateX(18px); }

/* Number input */
.setting-control { display: flex; align-items: center; gap: 6px; }
.number-input {
  width: 76px; padding: 7px 10px;
  background: var(--input); border: 1px solid var(--border-2);
  border-radius: var(--radius); color: var(--text);
  font-family: var(--font); font-size: 13px; text-align: right;
  transition: border-color 0.2s;
}
.number-input:focus { outline: none; border-color: var(--green); }
.setting-unit { font-size: 12px; color: var(--text-3); }

/* Select */
.select-input {
  padding: 8px 12px; background: var(--input);
  border: 1px solid var(--border-2); border-radius: var(--radius);
  color: var(--text); font-family: var(--font); font-size: 13px; cursor: pointer;
  transition: border-color 0.2s;
}
.select-input:focus { outline: none; border-color: var(--green); }

/* About card */
.about-card { display: flex; align-items: center; gap: 18px; padding: 20px 18px; }
.about-icon { width: 52px; height: 52px; border-radius: 13px; object-fit: cover; box-shadow: 0 2px 10px rgba(0,139,71,0.2); }
.about-info { display: flex; flex-direction: column; gap: 3px; }
.about-name { font-size: 15px; font-weight: 700; color: var(--text); }
.about-meta { display: flex; align-items: center; gap: 8px; }
.about-link { color: var(--green); text-decoration: none; }
.about-link:hover { text-decoration: underline; }

.badge-green-sm {
  font-size: 10px; font-weight: 700;
  background: rgba(0,139,71,0.1); color: var(--green);
  padding: 2px 8px; border-radius: 999px;
}

/* Spinner */
.spinner-xs {
  display: inline-block; width: 12px; height: 12px;
  border: 2px solid rgba(255,255,255,0.3); border-top-color: white;
  border-radius: 50%; animation: spin 0.8s linear infinite;
  vertical-align: middle;
}
@keyframes spin { to { transform: rotate(360deg); } }
</style>
