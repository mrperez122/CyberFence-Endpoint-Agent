<!-- Settings view -->
<script lang="ts">
  let realtimeMonitoring = true;
  let scanningEnabled    = true;
  let scanArchives       = true;
  let logLevel           = 'INFO';
  let maxFileSizeMb      = 256;
  let debounceMs         = 250;
  let saved              = false;

  function save() {
    saved = true;
    setTimeout(() => saved = false, 2500);
  }
</script>

<div class="page animate-in">
  <div class="page-header">
    <div>
      <h1 class="page-title">Settings</h1>
      <p class="page-sub">Configure the CyberFence endpoint agent</p>
    </div>
    <button class="btn btn-primary" on:click={save}>
      {#if saved}
        <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>
        Saved
      {:else}
        Save Changes
      {/if}
    </button>
  </div>

  <!-- Monitor section -->
  <div class="settings-section">
    <h2 class="section-title">File Monitoring</h2>
    <div class="settings-card card">
      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Real-time monitoring</span>
          <span class="setting-desc">Watch Downloads, Desktop, Documents for changes</span>
        </div>
        <label class="toggle">
          <input type="checkbox" bind:checked={realtimeMonitoring} />
          <span class="toggle-track"></span>
        </label>
      </div>
      <div class="setting-divider"></div>
      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Event debounce window</span>
          <span class="setting-desc">Milliseconds to wait before processing repeated events</span>
        </div>
        <div class="setting-control">
          <input class="number-input" type="number" bind:value={debounceMs} min="50" max="2000" step="50" />
          <span class="setting-unit">ms</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Scanner section -->
  <div class="settings-section">
    <h2 class="section-title">Scanner</h2>
    <div class="settings-card card">
      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Malware scanning</span>
          <span class="setting-desc">Enable ClamAV on-access scanning</span>
        </div>
        <label class="toggle">
          <input type="checkbox" bind:checked={scanningEnabled} />
          <span class="toggle-track"></span>
        </label>
      </div>
      <div class="setting-divider"></div>
      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Scan archives</span>
          <span class="setting-desc">Inspect .zip, .tar, .gz, and other archive formats</span>
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
          <span class="setting-desc">Skip files larger than this limit</span>
        </div>
        <div class="setting-control">
          <input class="number-input" type="number" bind:value={maxFileSizeMb} min="10" max="2048" step="10" />
          <span class="setting-unit">MB</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Logging section -->
  <div class="settings-section">
    <h2 class="section-title">Logging</h2>
    <div class="settings-card card">
      <div class="setting-row">
        <div class="setting-info">
          <span class="setting-label">Log level</span>
          <span class="setting-desc">Verbosity of agent log output</span>
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

  <!-- About section -->
  <div class="settings-section">
    <h2 class="section-title">About</h2>
    <div class="settings-card card about-card">
      <img src="/assets/app-icon.jpg" alt="CyberFence" class="about-icon" />
      <div>
        <div class="about-name">CyberFence Endpoint Protection</div>
        <div class="about-version text-muted text-sm">v0.1.0 · Phase 2 — Scanner</div>
        <div class="about-copy text-faint text-xs">© 2026 CyberFence / Perez Technology Group</div>
      </div>
    </div>
  </div>
</div>

<style>
.page { padding:28px 32px; max-height:100vh; overflow-y:auto; }
.page-header { display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:24px; }
.page-title  { font-size:22px; font-weight:700; margin-bottom:2px; }
.page-sub    { font-size:13px; color:var(--cf-text-2); font-weight:300; }

.settings-section { margin-bottom:22px; }
.section-title { font-size:13px; font-weight:700; color:var(--cf-text-2); text-transform:uppercase; letter-spacing:0.07em; margin-bottom:10px; }
.settings-card { padding:0; overflow:hidden; }

.setting-row {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 16px 18px;
}

.setting-divider { height:1px; background:var(--cf-border); margin:0; }

.setting-info { flex:1; }
.setting-label { display:block; font-size:13px; font-weight:600; color:var(--cf-text); margin-bottom:2px; }
.setting-desc  { font-size:11px; color:var(--cf-text-3); font-weight:300; }

/* Toggle */
.toggle { position:relative; cursor:pointer; }
.toggle input { display:none; }
.toggle-track {
  display: block;
  width: 40px; height: 22px;
  background: var(--cf-border-2);
  border-radius: 999px;
  position: relative;
  transition: background 0.2s;
}
.toggle-track::after {
  content: '';
  position: absolute;
  top: 3px; left: 3px;
  width: 16px; height: 16px;
  background: white;
  border-radius: 50%;
  transition: transform 0.2s;
}
.toggle input:checked ~ .toggle-track { background: var(--cf-green-2); }
.toggle input:checked ~ .toggle-track::after { transform: translateX(18px); }

/* Number input */
.setting-control { display:flex; align-items:center; gap:6px; }
.number-input {
  width: 72px;
  padding: 6px 10px;
  background: var(--cf-bg-input);
  border: 1px solid var(--cf-border-2);
  border-radius: var(--radius);
  color: var(--cf-text);
  font-family: var(--cf-font);
  font-size: 13px;
  text-align: right;
}
.number-input:focus { outline:none; border-color:var(--cf-green-3); }
.setting-unit { font-size:12px; color:var(--cf-text-3); }

.select-input {
  padding: 7px 12px;
  background: var(--cf-bg-input);
  border: 1px solid var(--cf-border-2);
  border-radius: var(--radius);
  color: var(--cf-text);
  font-family: var(--cf-font);
  font-size: 13px;
  cursor: pointer;
}
.select-input:focus { outline:none; border-color:var(--cf-green-3); }

/* About */
.about-card { display:flex; align-items:center; gap:16px; padding:18px; }
.about-icon { width:48px; height:48px; border-radius:12px; object-fit:cover; }
.about-name    { font-size:14px; font-weight:700; margin-bottom:2px; }
.about-version { margin-bottom:2px; }
</style>
