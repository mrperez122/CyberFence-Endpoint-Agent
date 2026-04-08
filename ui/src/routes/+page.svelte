<!-- Overview dashboard — CyberFence Endpoint Protection -->
<script lang="ts">
  import { status, scanHistory, threats, startQuickScan, scanState, scanProgress } from '$lib/stores';

  function fmt(n: number): string {
    return n >= 1_000_000 ? (n/1_000_000).toFixed(1)+'M'
         : n >= 1_000     ? (n/1_000).toFixed(1)+'K'
         : String(n);
  }

  function relTime(iso: string | null | undefined): string {
    if (!iso) return 'Never';
    const diff = Date.now() - new Date(iso).getTime();
    const h = Math.floor(diff / 3_600_000);
    if (h < 1)  return 'Just now';
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  }

  function fmtDur(secs: number): string {
    return secs < 60 ? `${secs}s` : `${Math.floor(secs/60)}m ${secs%60}s`;
  }

  $: recentThreats = ($threats ?? []).slice(0, 4);
  $: lastScan = ($scanHistory ?? [])[0];
  $: isScanning = $scanState === 'running';
  $: isProtected = $status?.protectionStatus === 'PROTECTED';
</script>

<div class="page animate-in">

  <!-- ── Page header ──────────────────────────────────────────────────────── -->
  <div class="page-header">
    <div>
      <h1 class="page-title">Overview</h1>
      <p class="page-sub">Real-time endpoint protection status</p>
    </div>
    <button class="btn btn-primary" on:click={startQuickScan} disabled={isScanning}>
      <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
      </svg>
      {isScanning ? 'Scanning…' : 'Quick Scan'}
    </button>
  </div>

  <!-- ── Scan progress banner ──────────────────────────────────────────────── -->
  {#if isScanning && $scanProgress}
    <div class="scan-banner">
      <div class="scan-spinner-sm"></div>
      <div class="scan-banner-info">
        <span class="scan-banner-label">Scan in progress</span>
        <span class="scan-banner-file">{$scanProgress.currentFile ?? 'Initializing…'}</span>
      </div>
      <span class="scan-pct">{$scanProgress.percent}%</span>
      <div class="scan-bar-wrap">
        <div class="scan-bar-fill" style="width:{$scanProgress.percent}%">
          <div class="scan-sweep"></div>
        </div>
      </div>
    </div>
  {/if}

  <!-- ── Hero status card ──────────────────────────────────────────────────── -->
  <div class="hero-card" class:protected={isProtected} class:at-risk={!isProtected}>
    <div class="hero-icon-wrap">
      <img src="/assets/app-icon.jpg" alt="CyberFence" class="hero-icon" />
      {#if isProtected}
        <div class="hero-ring"></div>
      {/if}
    </div>
    <div class="hero-info">
      {#if isProtected}
        <span class="hero-badge badge-protected">● Protected</span>
        <h2 class="hero-title">Your device is protected</h2>
      {:else}
        <span class="hero-badge badge-warn">⚠ Action Required</span>
        <h2 class="hero-title">Protection needs attention</h2>
      {/if}
      <p class="hero-sub">
        Last scan: <strong>{relTime($status?.lastScanTime)}</strong>
        &nbsp;·&nbsp;
        Engine: CyberFence Engine v{$status?.definitionsVersion ?? '—'}
        &nbsp;·&nbsp;
        Definitions: {$status?.definitionsAgeHours ?? 0}h old
      </p>
    </div>
    <div class="hero-actions">
      <a href="/scan" class="btn btn-outline btn-sm">Full Scan</a>
    </div>
  </div>

  <!-- ── KPI grid ──────────────────────────────────────────────────────────── -->
  <div class="kpi-row">
    <div class="kpi-card">
      <div class="kpi-icon kpi-icon-green">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <div class="kpi-body">
        <span class="kpi-val green">{fmt($status?.filesMonitoredToday ?? 0)}</span>
        <span class="kpi-label">Files Monitored Today</span>
      </div>
    </div>

    <div class="kpi-card">
      <div class="kpi-icon" class:kpi-icon-danger={($status?.threatsToday ?? 0) > 0} class:kpi-icon-muted={($status?.threatsToday ?? 0) === 0}>
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path d="m10.29 3.86-8.17 14.17A2 2 0 0 0 3.86 21h16.28a2 2 0 0 0 1.74-2.97L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      </div>
      <div class="kpi-body">
        <span class="kpi-val" class:danger={($status?.threatsToday ?? 0) > 0}>{$status?.threatsToday ?? 0}</span>
        <span class="kpi-label">Threats Today</span>
      </div>
    </div>

    <div class="kpi-card">
      <div class="kpi-icon kpi-icon-info">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <circle cx="12" cy="12" r="10"/>
          <polyline points="12 6 12 12 16 14"/>
        </svg>
      </div>
      <div class="kpi-body">
        <span class="kpi-val">{relTime(lastScan?.startedAt)}</span>
        <span class="kpi-label">Last Scan</span>
      </div>
    </div>

    <div class="kpi-card">
      <div class="kpi-icon kpi-icon-muted">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
        </svg>
      </div>
      <div class="kpi-body">
        <span class="kpi-val">{$status?.threatsTotal ?? 0}</span>
        <span class="kpi-label">All-Time Threats</span>
      </div>
    </div>
  </div>

  <!-- ── Two-column lower section ─────────────────────────────────────────── -->
  <div class="lower-grid">

    <!-- Recent threats -->
    <div class="card section-card">
      <div class="section-header">
        <h3 class="section-title">Recent Threats</h3>
        <a href="/threats" class="section-link">View all →</a>
      </div>
      {#if recentThreats.length === 0}
        <div class="empty-state">
          <svg width="32" height="32" fill="none" stroke="var(--green)" stroke-width="1.5" viewBox="0 0 24 24">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <polyline stroke="var(--green)" points="9 12 11 14 15 10"/>
          </svg>
          <p>No threats detected</p>
        </div>
      {:else}
        <div class="threat-list">
          {#each recentThreats as t}
            <div class="threat-row">
              <div class="threat-sev-dot" class:sev-critical={t.verdict === 'INFECTED'} class:sev-warn={t.verdict === 'SUSPICIOUS'}></div>
              <div class="threat-info">
                <span class="threat-name">{t.threatName}</span>
                <span class="threat-path">{t.path?.split('\\').pop() ?? t.path}</span>
              </div>
              <span class="threat-time text-xs text-faint">{relTime(t.detectedAt)}</span>
            </div>
          {/each}
        </div>
      {/if}
    </div>

    <!-- Last scan summary -->
    <div class="card section-card">
      <div class="section-header">
        <h3 class="section-title">Last Scan</h3>
        <a href="/history" class="section-link">History →</a>
      </div>
      {#if lastScan}
        <div class="scan-summary">
          <div class="scan-sum-row">
            <span class="scan-sum-label">Type</span>
            <span class="scan-sum-val">{lastScan.scanType === 'QUICK' ? 'Quick Scan' : 'Full Scan'}</span>
          </div>
          <div class="scan-sum-row">
            <span class="scan-sum-label">Started</span>
            <span class="scan-sum-val">{relTime(lastScan.startedAt)}</span>
          </div>
          <div class="scan-sum-row">
            <span class="scan-sum-label">Duration</span>
            <span class="scan-sum-val">{fmtDur(lastScan.durationSecs)}</span>
          </div>
          <div class="scan-sum-row">
            <span class="scan-sum-label">Files Scanned</span>
            <span class="scan-sum-val">{fmt(lastScan.filesScanned)}</span>
          </div>
          <div class="scan-sum-row">
            <span class="scan-sum-label">Threats Found</span>
            <span class="scan-sum-val" class:text-danger={lastScan.threatsFound > 0}>{lastScan.threatsFound}</span>
          </div>
          <div class="scan-sum-row">
            <span class="scan-sum-label">Result</span>
            <span class="scan-sum-val">
              {#if lastScan.threatsFound === 0}
                <span class="badge badge-protected badge-sm">Clean</span>
              {:else}
                <span class="badge badge-danger badge-sm">{lastScan.threatsFound} Threat{lastScan.threatsFound > 1 ? 's' : ''}</span>
              {/if}
            </span>
          </div>
        </div>
      {:else}
        <div class="empty-state">
          <svg width="32" height="32" fill="none" stroke="var(--text-3)" stroke-width="1.5" viewBox="0 0 24 24">
            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
          </svg>
          <p>No scans run yet</p>
          <a href="/scan" class="btn btn-outline btn-sm" style="margin-top:10px">Run First Scan</a>
        </div>
      {/if}
    </div>

  </div>

</div>

<style>
.page { padding: 28px 32px; max-height: 100vh; overflow-y: auto; }

.page-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 24px; }
.page-title  { font-size: 22px; font-weight: 700; color: var(--text); margin-bottom: 3px; }
.page-sub    { font-size: 13px; color: var(--text-2); font-weight: 300; }

/* ── Scan banner ────────────────────────────────────────────────────── */
.scan-banner {
  display: flex; align-items: center; gap: 12px;
  background: rgba(0,139,71,0.06);
  border: 1px solid rgba(0,139,71,0.2);
  border-radius: var(--radius-lg);
  padding: 12px 16px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}
.scan-spinner-sm {
  width: 18px; height: 18px; border-radius: 50%;
  border: 2px solid var(--border-2);
  border-top-color: var(--green);
  animation: spin 0.8s linear infinite;
  flex-shrink: 0;
}
.scan-banner-info  { flex: 1; min-width: 0; }
.scan-banner-label { display: block; font-size: 12px; font-weight: 700; color: var(--green); }
.scan-banner-file  { display: block; font-size: 11px; color: var(--text-3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.scan-pct { font-size: 13px; font-weight: 700; color: var(--green); }
.scan-bar-wrap { width: 100%; height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; }
.scan-bar-fill { height: 100%; background: var(--green); border-radius: 2px; transition: width 0.3s ease; position: relative; overflow: hidden; }
.scan-sweep {
  position: absolute; top: 0; left: -100%; width: 60%; height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
  animation: sweep 1.5s linear infinite;
}

/* ── Hero card ──────────────────────────────────────────────────────── */
.hero-card {
  display: flex; align-items: center; gap: 20px;
  padding: 22px 24px;
  border-radius: var(--radius-lg);
  border: 1px solid;
  margin-bottom: 20px;
  transition: all 0.3s;
}
.hero-card.protected {
  background: linear-gradient(135deg, rgba(0,139,71,0.05) 0%, rgba(171,229,81,0.06) 100%);
  border-color: rgba(0,139,71,0.2);
}
.hero-card.at-risk {
  background: rgba(230,126,34,0.04);
  border-color: rgba(230,126,34,0.2);
}

.hero-icon-wrap { position: relative; flex-shrink: 0; }
.hero-icon { width: 54px; height: 54px; border-radius: 14px; object-fit: cover; box-shadow: 0 2px 12px rgba(0,139,71,0.2); }
.hero-ring {
  position: absolute; inset: -5px; border-radius: 18px;
  border: 2px solid rgba(0,139,71,0.3);
  animation: ring-pulse 3s ease-in-out infinite;
}

.hero-info { flex: 1; }
.hero-badge { display: inline-block; font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 999px; margin-bottom: 6px; letter-spacing: 0.02em; }
.badge-protected { background: rgba(0,139,71,0.1); color: var(--green); }
.badge-warn      { background: rgba(230,126,34,0.1); color: var(--warn); }
.badge-danger    { background: var(--danger-lite); color: var(--danger); }

.hero-title { font-size: 17px; font-weight: 700; color: var(--text); margin-bottom: 5px; }
.hero-sub   { font-size: 12px; color: var(--text-3); font-weight: 400; }
.hero-sub strong { color: var(--text-2); font-weight: 600; }

.hero-actions { margin-left: auto; }

/* ── KPI row ────────────────────────────────────────────────────────── */
.kpi-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }

.kpi-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  transition: box-shadow 0.2s;
}
.kpi-card:hover { box-shadow: 0 2px 10px rgba(0,0,0,0.06); }

.kpi-icon {
  width: 36px; height: 36px; border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
}
.kpi-icon-green  { background: rgba(0,139,71,0.1); color: var(--green); }
.kpi-icon-danger { background: var(--danger-lite); color: var(--danger); }
.kpi-icon-info   { background: var(--info-lite); color: var(--info); }
.kpi-icon-muted  { background: var(--card-alt); color: var(--text-3); }

.kpi-body { display: flex; flex-direction: column; min-width: 0; }
.kpi-val   { font-size: 20px; font-weight: 800; color: var(--text); line-height: 1.2; }
.kpi-val.green  { color: var(--green); }
.kpi-val.danger { color: var(--danger); }
.kpi-label { font-size: 11px; color: var(--text-3); font-weight: 500; margin-top: 2px; white-space: nowrap; }

/* ── Lower grid ─────────────────────────────────────────────────────── */
.lower-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }

.section-card { padding: 0; overflow: hidden; }
.section-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 14px 18px 12px;
  border-bottom: 1px solid var(--border);
}
.section-title { font-size: 13px; font-weight: 700; color: var(--text); }
.section-link  { font-size: 12px; color: var(--green); font-weight: 600; text-decoration: none; }
.section-link:hover { text-decoration: underline; }

/* Threat list */
.threat-list { padding: 8px 0; }
.threat-row {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 18px;
  transition: background 0.15s;
}
.threat-row:hover { background: var(--card-alt); }

.threat-sev-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.sev-critical { background: var(--danger); }
.sev-warn     { background: var(--warn); }

.threat-info { flex: 1; min-width: 0; }
.threat-name { display: block; font-size: 12px; font-weight: 600; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.threat-path { display: block; font-size: 11px; color: var(--text-3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.threat-time { flex-shrink: 0; }

/* Scan summary */
.scan-summary { padding: 8px 0; }
.scan-sum-row {
  display: flex; justify-content: space-between; align-items: center;
  padding: 9px 18px;
}
.scan-sum-row:not(:last-child) { border-bottom: 1px solid var(--border); }
.scan-sum-label { font-size: 12px; color: var(--text-3); font-weight: 400; }
.scan-sum-val   { font-size: 12px; color: var(--text); font-weight: 600; }

.badge-sm { font-size: 10px; padding: 2px 8px; }

/* Empty state */
.empty-state {
  display: flex; flex-direction: column; align-items: center;
  justify-content: center; gap: 8px;
  padding: 32px 16px;
  color: var(--text-3);
  font-size: 13px;
}

/* Animations */
@keyframes spin      { to { transform: rotate(360deg); } }
@keyframes sweep     { to { left: 200%; } }
@keyframes ring-pulse { 0%,100% { opacity:0.3; transform:scale(1); } 50% { opacity:0.7; transform:scale(1.04); } }
</style>
