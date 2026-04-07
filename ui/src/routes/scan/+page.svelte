<!-- Scan page -->
<script lang="ts">
  let scanState: 'idle' | 'running' | 'complete' = 'idle';
  let scanType = '';
  let progress = 0;
  let filesScanned = 0;
  let threatsFound = 0;
  let currentFile = '';
  let totalFiles = 0;
  let duration = 0;
  let timer: ReturnType<typeof setInterval>;

  async function startScan(type: 'quick' | 'full') {
    if (scanState === 'running') return;
    scanType = type === 'quick' ? 'Quick Scan' : 'Full Scan';
    scanState = 'running';
    progress = 0; filesScanned = 0; threatsFound = 0; duration = 0;
    totalFiles = type === 'quick' ? 900 : 48000;

    // Simulate progress for demo
    const startTime = Date.now();
    timer = setInterval(() => {
      duration = Math.floor((Date.now() - startTime) / 1000);
      filesScanned = Math.min(filesScanned + Math.floor(Math.random() * 50 + 20), totalFiles);
      progress = Math.floor((filesScanned / totalFiles) * 100);
      currentFile = mockFiles[Math.floor(Math.random() * mockFiles.length)];
      if (filesScanned >= totalFiles) {
        clearInterval(timer);
        scanState = 'complete';
        progress = 100;
      }
    }, 120);

    // Actually call the agent
    try {
      if ((window as any).__TAURI_INTERNALS__) {
        const { invoke } = await import('@tauri-apps/api/core');
        await invoke(type === 'quick' ? 'run_quick_scan' : 'run_full_scan');
      }
    } catch {}
  }

  function cancelScan() {
    clearInterval(timer);
    scanState = 'idle';
  }

  function formatSecs(s: number) {
    if (s < 60) return `${s}s`;
    return `${Math.floor(s/60)}m ${s%60}s`;
  }

  const mockFiles = [
    'C:\\Users\\Carlos\\Downloads\\setup.exe',
    'C:\\Users\\Carlos\\Desktop\\notes.txt',
    'C:\\Users\\Carlos\\Documents\\report.pdf',
    'C:\\Program Files\\Chrome\\chrome.exe',
    'C:\\Windows\\System32\\notepad.exe',
  ];
</script>

<div class="page animate-in">
  <div class="page-header">
    <div>
      <h1 class="page-title">Scan</h1>
      <p class="page-sub">Run a malware scan on your system</p>
    </div>
  </div>

  {#if scanState === 'idle'}
    <!-- Scan options -->
    <div class="scan-options">
      <button class="scan-option-card" on:click={() => startScan('quick')}>
        <div class="scan-option-icon green">
          <svg width="28" height="28" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24">
            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
          </svg>
        </div>
        <div class="scan-option-info">
          <h3>Quick Scan</h3>
          <p>Scans Downloads, Desktop, Documents, and Startup folders. Takes 2–5 minutes.</p>
          <span class="scan-meta">~900 files · ~3 min</span>
        </div>
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="color:var(--cf-text-3);flex-shrink:0">
          <path d="m9 18 6-6-6-6"/>
        </svg>
      </button>

      <button class="scan-option-card" on:click={() => startScan('full')}>
        <div class="scan-option-icon blue">
          <svg width="28" height="28" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24">
            <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
          </svg>
        </div>
        <div class="scan-option-info">
          <h3>Full Scan</h3>
          <p>Complete scan of all drives and directories. Recommended weekly.</p>
          <span class="scan-meta">~48,000 files · ~20 min</span>
        </div>
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="color:var(--cf-text-3);flex-shrink:0">
          <path d="m9 18 6-6-6-6"/>
        </svg>
      </button>
    </div>

  {:else if scanState === 'running'}
    <!-- Live progress -->
    <div class="scan-running card">
      <div class="scan-running-header">
        <div class="scan-spinner"></div>
        <div>
          <h2 class="scan-running-title">{scanType} in progress</h2>
          <p class="text-muted text-sm">{formatSecs(duration)} elapsed · {threatsFound} threats found</p>
        </div>
        <button class="btn btn-outline" on:click={cancelScan} style="margin-left:auto">Cancel</button>
      </div>

      <div class="progress-bar">
        <div class="progress-fill" style="width:{progress}%"></div>
        <div class="progress-sweep" style="width:{progress}%"></div>
      </div>
      <div class="progress-row">
        <span class="text-faint text-xs">{filesScanned.toLocaleString()} / {totalFiles.toLocaleString()} files</span>
        <span class="text-green text-sm" style="font-weight:700">{progress}%</span>
      </div>

      <div class="current-file text-faint text-xs" title={currentFile}>
        Scanning: {currentFile}
      </div>
    </div>

  {:else}
    <!-- Complete -->
    <div class="scan-complete card">
      <div class="complete-icon">
        <svg width="40" height="40" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="color:var(--cf-green-1)">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>
        </svg>
      </div>
      <h2 class="complete-title">
        {threatsFound === 0 ? 'No threats found' : `${threatsFound} threat${threatsFound > 1 ? 's' : ''} detected`}
      </h2>
      <p class="text-muted">
        Scanned {totalFiles.toLocaleString()} files in {formatSecs(duration)}
      </p>
      <button class="btn btn-primary" on:click={() => scanState = 'idle'} style="margin-top:20px">
        Run Another Scan
      </button>
    </div>
  {/if}
</div>

<style>
.page { padding:28px 32px; }
.page-header { margin-bottom:24px; }
.page-title  { font-size:22px; font-weight:700; color:var(--cf-text); margin-bottom:2px; }
.page-sub    { font-size:13px; color:var(--cf-text-2); font-weight:300; }

.scan-options { display:flex; flex-direction:column; gap:12px; }

.scan-option-card {
  display: flex;
  align-items: center;
  gap: 20px;
  padding: 22px 20px;
  background: var(--cf-bg-card);
  border: 1px solid var(--cf-border);
  border-radius: var(--radius-lg);
  text-align: left;
  font-family: var(--cf-font);
  color: var(--cf-text);
  cursor: pointer;
  transition: all 0.15s;
  width: 100%;
}
.scan-option-card:hover { border-color:var(--cf-green-3); background:var(--cf-bg-card-2); }

.scan-option-icon {
  width: 56px; height: 56px;
  border-radius: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.scan-option-icon.green { background:rgba(171,229,81,0.1);  color:var(--cf-green-1); border:1px solid rgba(171,229,81,0.2); }
.scan-option-icon.blue  { background:rgba(91,184,255,0.1);  color:var(--cf-info);    border:1px solid rgba(91,184,255,0.2); }

.scan-option-info { flex:1; }
.scan-option-info h3    { font-size:15px; font-weight:700; margin-bottom:4px; }
.scan-option-info p     { font-size:12px; color:var(--cf-text-2); font-weight:300; margin-bottom:6px; }
.scan-meta              { font-size:11px; color:var(--cf-text-3); font-weight:500; }

/* Running */
.scan-running { }
.scan-running-header { display:flex; align-items:center; gap:16px; margin-bottom:20px; }

.scan-spinner {
  width: 36px; height: 36px;
  border: 3px solid var(--cf-border);
  border-top-color: var(--cf-green-1);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  flex-shrink: 0;
}
@keyframes spin { to { transform: rotate(360deg); } }

.scan-running-title { font-size:16px; font-weight:700; margin-bottom:2px; }

.progress-bar {
  height: 8px;
  background: var(--cf-border);
  border-radius: 999px;
  overflow: hidden;
  position: relative;
  margin-bottom: 8px;
}
.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--cf-green-4), var(--cf-green-1));
  border-radius: 999px;
  transition: width 0.2s ease;
}
.progress-sweep {
  position: absolute;
  top: 0; left: 0;
  height: 100%;
  background: linear-gradient(90deg, transparent 60%, rgba(255,255,255,0.3) 100%);
  animation: scan-sweep 1.5s ease-in-out infinite;
  border-radius: 999px;
}
.progress-row { display:flex; justify-content:space-between; margin-bottom:12px; }
.current-file {
  padding: 8px 12px;
  background: var(--cf-bg-input);
  border-radius: var(--radius);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Complete */
.scan-complete {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  padding: 48px 24px;
}
.complete-icon {
  width: 80px; height: 80px;
  background: rgba(171,229,81,0.1);
  border: 2px solid rgba(171,229,81,0.3);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 16px;
}
.complete-title { font-size:22px; font-weight:700; margin-bottom:8px; }
</style>
