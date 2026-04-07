<script lang="ts">
  import { scanState, scanProgress, startQuickScan, startFullScan, resetScan } from '$lib/stores';

  function fmtFiles(n: number) {
    return n >= 1000 ? (n/1000).toFixed(1)+'K' : String(n);
  }
  function fmtDur(ms: number) {
    const s = Math.floor(ms / 1000);
    return s < 60 ? `${s}s` : `${Math.floor(s/60)}m ${s%60}s`;
  }
</script>

<div class="page animate-in">
  <div class="page-header">
    <div>
      <h1 class="page-title">Scan</h1>
      <p class="page-sub">Run a malware scan using the CyberFence Engine</p>
    </div>
  </div>

  {#if $scanState === 'idle'}

    <!-- Scan options -->
    <div class="scan-options">
      <button class="scan-card" on:click={startQuickScan}>
        <div class="scan-icon green">
          <svg width="26" height="26" fill="none" stroke="var(--green)" stroke-width="1.8" viewBox="0 0 24 24">
            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
          </svg>
        </div>
        <div class="scan-info">
          <div class="scan-title">Quick Scan</div>
          <div class="scan-desc">Scans Downloads, Desktop, Documents, Temp and Startup folders.</div>
          <div class="scan-meta">~900 files · ~3 minutes</div>
        </div>
        <svg width="15" height="15" fill="none" stroke="var(--text-3)" stroke-width="2" viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></svg>
      </button>

      <button class="scan-card" on:click={startFullScan}>
        <div class="scan-icon blue">
          <svg width="26" height="26" fill="none" stroke="var(--info)" stroke-width="1.8" viewBox="0 0 24 24">
            <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
          </svg>
        </div>
        <div class="scan-info">
          <div class="scan-title">Full Scan</div>
          <div class="scan-desc">Complete scan of all drives and system directories. Recommended weekly.</div>
          <div class="scan-meta">~48,000 files · ~20 minutes</div>
        </div>
        <svg width="15" height="15" fill="none" stroke="var(--text-3)" stroke-width="2" viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></svg>
      </button>
    </div>

  {:else if $scanState === 'running' && $scanProgress}

    <!-- Running scan -->
    <div class="scan-running card">
      <div class="sr-header">
        <div class="sr-spinner"></div>
        <div>
          <div class="sr-title">Scan in progress</div>
          <div class="text-faint text-xs">{$scanProgress.threatsFound} threats found so far</div>
        </div>
        <button class="btn btn-outline" style="margin-left:auto;font-size:12px" on:click={resetScan}>Cancel</button>
      </div>

      <div class="progress-track">
        <div class="progress-fill" style="width:{$scanProgress.percent}%">
          <div class="progress-sweep"></div>
        </div>
      </div>
      <div class="sr-stats">
        <span class="text-faint text-xs">{fmtFiles($scanProgress.scannedFiles)} / {fmtFiles($scanProgress.totalFiles)} files</span>
        <span class="text-sm" style="font-weight:700;color:var(--green)">{$scanProgress.percent}%</span>
      </div>
      {#if $scanProgress.currentFile}
        <div class="sr-file">{$scanProgress.currentFile}</div>
      {/if}
    </div>

  {:else if $scanState === 'complete'}

    <!-- Complete -->
    <div class="scan-complete card">
      <div class="sc-icon">
        <svg width="36" height="36" fill="none" stroke="var(--green)" stroke-width="2" viewBox="0 0 24 24">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>
        </svg>
      </div>
      <h2 class="sc-title">Scan complete</h2>
      <p class="text-muted">
        {$scanProgress ? fmtFiles($scanProgress.totalFiles) : '—'} files scanned ·
        {$scanProgress?.threatsFound ?? 0} threats found
      </p>
      <button class="btn btn-primary" on:click={resetScan} style="margin-top:18px">
        Run Another Scan
      </button>
    </div>

  {/if}
</div>

<style>
.page        { padding: 24px 28px; }
.page-header { margin-bottom: 20px; }
.page-title  { font-size: 20px; font-weight: 700; margin-bottom: 1px; }
.page-sub    { font-size: 12px; color: var(--text-2); font-weight: 300; }

.scan-options { display: flex; flex-direction: column; gap: 11px; }
.scan-card {
  display: flex; align-items: center; gap: 18px;
  padding: 20px 18px; background: var(--card);
  border: 1px solid var(--border); border-radius: var(--radius-lg);
  text-align: left; font-family: var(--font);
  color: var(--text); cursor: pointer; transition: all 0.15s; width: 100%;
}
.scan-card:hover { border-color: var(--green); background: var(--card-alt); }
.scan-icon {
  width: 52px; height: 52px; border-radius: 12px;
  display: flex; align-items: center; justify-content: center; flex-shrink: 0;
}
.scan-icon.green { background: rgba(0,139,71,0.1); border: 1px solid rgba(0,139,71,0.2); }
.scan-icon.blue  { background: rgba(26,115,232,0.1); border: 1px solid rgba(26,115,232,0.2); }
.scan-info   { flex: 1; }
.scan-title  { font-size: 14px; font-weight: 700; margin-bottom: 3px; }
.scan-desc   { font-size: 12px; color: var(--text-2); font-weight: 300; margin-bottom: 5px; }
.scan-meta   { font-size: 11px; color: var(--text-3); font-weight: 500; }

/* Running */
.scan-running { }
.sr-header    { display: flex; align-items: center; gap: 14px; margin-bottom: 18px; }
.sr-spinner   { width: 28px; height: 28px; border-radius: 50%; border: 3px solid var(--border-2); border-top-color: var(--green); animation: spin 0.8s linear infinite; flex-shrink: 0; }
.sr-title     { font-size: 15px; font-weight: 700; margin-bottom: 2px; }
.progress-track { height: 7px; background: var(--border); border-radius: 999px; overflow: hidden; margin-bottom: 7px; position: relative; }
.progress-fill  { height: 100%; background: linear-gradient(90deg, var(--green), var(--green-4)); border-radius: 999px; transition: width 0.2s ease; position: relative; overflow: hidden; }
.progress-sweep { position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: linear-gradient(90deg, transparent 60%, rgba(255,255,255,0.4)); animation: scan-sweep 1.5s ease-in-out infinite; }
.sr-stats { display: flex; justify-content: space-between; margin-bottom: 10px; }
.sr-file  { padding: 7px 10px; background: var(--input); border-radius: var(--radius); font-size: 10px; color: var(--text-3); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* Complete */
.scan-complete { display: flex; flex-direction: column; align-items: center; text-align: center; padding: 48px 24px; }
.sc-icon  { width: 72px; height: 72px; background: rgba(0,139,71,0.1); border: 2px solid rgba(0,139,71,0.25); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-bottom: 14px; }
.sc-title { font-size: 20px; font-weight: 700; margin-bottom: 6px; }
</style>
