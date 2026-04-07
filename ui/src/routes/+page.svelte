<!-- Overview dashboard -->
<script lang="ts">
  import { status, scanHistory, threats, startQuickScan, scanState, scanProgress } from '$lib/stores';

  function fmt(n: number): string {
    return n >= 1_000_000 ? (n/1_000_000).toFixed(1)+'M'
         : n >= 1_000     ? (n/1_000).toFixed(1)+'K'
         : String(n);
  }

  function relTime(iso: string | null): string {
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

  $: recentThreats = $threats.slice(0, 3);
  $: lastScan = $scanHistory[0];
  $: isScanning = $scanState === 'running';
</script>

<div class="page animate-in">

  <!-- Header -->
  <div class="page-header">
    <div>
      <h1 class="page-title">Overview</h1>
      <p class="page-sub">System protection status</p>
    </div>
    <button class="btn btn-primary" on:click={startQuickScan} disabled={isScanning}>
      <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
      </svg>
      {isScanning ? 'Scanning…' : 'Quick Scan'}
    </button>
  </div>

  <!-- Scan progress banner -->
  {#if isScanning && $scanProgress}
    <div class="scan-banner">
      <div class="scan-spinner-sm"></div>
      <div class="scan-banner-info">
        <span class="scan-banner-label">Scan in progress</span>
        <span class="scan-banner-file">{$scanProgress.currentFile ?? '…'}</span>
      </div>
      <span class="scan-pct">{$scanProgress.percent}%</span>
      <div class="scan-bar-wrap">
        <div class="scan-bar-fill" style="width:{$scanProgress.percent}%">
          <div class="scan-sweep"></div>
        </div>
      </div>
    </div>
  {/if}

  <!-- Hero status card -->
  <div class="hero-card" class:protected={$status?.protectionStatus === 'PROTECTED'}
                         class:at-risk={$status?.protectionStatus !== 'PROTECTED' && $status?.protectionStatus !== 'SCANNING'}>
    <div class="hero-icon-wrap">
      <img src="/assets/app-icon.jpg" alt="CyberFence" class="hero-icon" />
      <div class="hero-ring"></div>
    </div>
    <div class="hero-info">
      <div class="hero-badge-row">
        {#if $status?.protectionStatus === 'PROTECTED'}
          <span class="badge badge-protected">● Protected</span>
        {:else if $status?.protectionStatus === 'AT_RISK'}
          <span class="badge badge-warn">⚠ At Risk</span>
        {:else}
          <span class="badge badge-muted">◌ Loading…</span>
        {/if}
      </div>
      <h2 class="hero-title">
        {$status?.protectionStatus === 'PROTECTED' ? 'Your device is protected' : 'Action required'}
      </h2>
      <p class="hero-sub">
        Last scan: {relTime($status?.lastScanTime ?? null)} ·
        Engine: v{$status?.definitionsVersion ?? '—'} ({$status?.definitionsAgeHours ?? 0}h old) ·
        CyberFence Engine active
      </p>
    </div>
  </div>

  <!-- KPI cards -->
  <div class="kpi-row">
    <div class="kpi-card">
      <span class="kpi-label">Files Monitored</span>
      <span class="kpi-val green">{fmt($status?.filesMonitoredToday ?? 0)}</span>
      <span class="kpi-sub">today</span>
    </div>
    <div class="kpi-card">
      <span class="kpi-label">Threats (All Time)</span>
      <span class="kpi-val" class:danger={($status?.threatsTotal ?? 0) > 0}>{$status?.threatsTotal ?? 0}</span>
      <span class="kpi-sub">detected</span>
    </div>
    <div class="kpi-card">
      <span class="kpi-label">Today's Threats</span>
      <span class="kpi-val" class:danger={($status?.threatsToday ?? 0) > 0}>{$status?.threatsToday ?? 0}</span>
      <span class="kpi-sub">past 24h</span>
    </div>
    <div class="kpi-card">
      <span class="kpi-label">Definitions Age</span>
      <span class="kpi-val" class:warn-val={($status?.definitionsAgeHours ?? 0) > 24}>
        {$status?.definitionsAgeHours ?? 0}h
      </span>
      <span class="kpi-sub">{($status?.definitionsAgeHours ?? 0) <= 24 ? 'up to date' : 'outdated'}</span>
    </div>
  </div>

  <!-- Feature status row -->
  <div class="features-row">
    <div class="feat">
      <span class="feat-dot" class:on={$status?.realtimeMonitoring}></span>
      <span class="feat-label">Real-time monitoring</span>
      <span class="feat-state" class:on={$status?.realtimeMonitoring}>{$status?.realtimeMonitoring ? 'ON' : 'OFF'}</span>
    </div>
    <div class="feat">
      <span class="feat-dot" class:on={$status?.scanningEnabled}></span>
      <span class="feat-label">Malware scanning</span>
      <span class="feat-state" class:on={$status?.scanningEnabled}>{$status?.scanningEnabled ? 'ON' : 'OFF'}</span>
    </div>
    <div class="feat">
      <span class="feat-dot on"></span>
      <span class="feat-label">CyberFence Engine</span>
      <span class="feat-state on">Active</span>
    </div>
  </div>

  <!-- Recent threats -->
  {#if recentThreats.length > 0}
    <div class="section-head">
      <h3 class="section-title">Recent Threats</h3>
      <a href="/threats" class="btn btn-ghost text-xs">View all →</a>
    </div>
    <div class="threat-mini-list">
      {#each recentThreats as t (t.id)}
        <div class="threat-mini" class:infected={t.verdict === 'INFECTED'}>
          <div class="threat-mini-icon">
            {#if t.verdict === 'INFECTED'}
              <svg width="16" height="16" fill="none" stroke="var(--danger)" stroke-width="2" viewBox="0 0 24 24"><path d="m10.29 3.86-8.17 14.17A2 2 0 0 0 3.86 21h16.28a2 2 0 0 0 1.74-2.97L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            {:else}
              <svg width="16" height="16" fill="none" stroke="var(--warn)" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            {/if}
          </div>
          <div class="threat-mini-info">
            <span class="threat-mini-name">{t.threatName}</span>
            <span class="threat-mini-path">{t.path.split(/[/\\]/).slice(-2).join('/')}</span>
          </div>
          <span class="badge {t.actionTaken === 'QUARANTINED' ? 'badge-quarantined' : 'badge-info'}">{t.actionTaken}</span>
        </div>
      {/each}
    </div>
  {/if}

  <!-- Last scan summary -->
  {#if lastScan}
    <div class="section-head" style="margin-top:16px">
      <h3 class="section-title">Last Scan</h3>
      <a href="/history" class="btn btn-ghost text-xs">View history →</a>
    </div>
    <div class="last-scan-card card">
      <div class="last-scan-row">
        <span class="badge badge-muted">{lastScan.scanType.replace('_',' ')}</span>
        <span class="text-faint text-xs">{relTime(lastScan.completedAt)}</span>
      </div>
      <div class="last-scan-stats">
        <div><span class="ls-num">{fmt(lastScan.filesScanned)}</span><span class="ls-label">files scanned</span></div>
        <div><span class="ls-num" class:danger={lastScan.threatsFound > 0}>{lastScan.threatsFound}</span><span class="ls-label">threats found</span></div>
        <div><span class="ls-num">{fmtDur(lastScan.durationSecs)}</span><span class="ls-label">duration</span></div>
      </div>
    </div>
  {/if}

</div>

<style>
.page         { padding: 24px 28px; max-height: 100vh; overflow-y: auto; }
.page-header  { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 18px; }
.page-title   { font-size: 20px; font-weight: 700; margin-bottom: 1px; }
.page-sub     { font-size: 12px; color: var(--text-2); font-weight: 300; }

/* Scan banner */
.scan-banner {
  display: grid; grid-template-columns: auto 1fr auto;
  align-items: center; gap: 12px;
  padding: 12px 16px;
  background: var(--green-lite);
  border: 1px solid rgba(0,139,71,0.2);
  border-radius: var(--radius);
  margin-bottom: 16px; position: relative;
}
.scan-spinner-sm {
  width: 18px; height: 18px; border-radius: 50%;
  border: 2px solid rgba(0,139,71,0.2);
  border-top-color: var(--green);
  animation: spin 0.7s linear infinite; flex-shrink: 0;
}
.scan-banner-info { min-width: 0; }
.scan-banner-label { display: block; font-size: 12px; font-weight: 600; color: var(--green); }
.scan-banner-file  { display: block; font-size: 10px; color: var(--text-3); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.scan-pct { font-size: 12px; font-weight: 700; color: var(--green); }
.scan-bar-wrap {
  grid-column: 1 / -1;
  height: 4px; background: var(--border-2); border-radius: 999px; overflow: hidden;
}
.scan-bar-fill {
  height: 100%; background: var(--green); border-radius: 999px;
  transition: width 0.2s ease; position: relative; overflow: hidden;
}
.scan-sweep {
  position: absolute; top: 0; left: 0; right: 0; bottom: 0;
  background: linear-gradient(90deg, transparent 60%, rgba(255,255,255,0.4));
  animation: scan-sweep 1.5s ease-in-out infinite;
}

/* Hero */
.hero-card {
  display: flex; align-items: center; gap: 20px;
  padding: 20px 22px; border-radius: var(--radius-lg);
  border: 1px solid; margin-bottom: 14px;
  transition: all 0.2s;
}
.hero-card.protected {
  background: linear-gradient(135deg, rgba(0,139,71,0.07), rgba(244,249,244,0.95));
  border-color: rgba(0,139,71,0.18);
}
.hero-card.at-risk {
  background: linear-gradient(135deg, rgba(230,126,34,0.07), rgba(244,249,244,0.95));
  border-color: rgba(230,126,34,0.2);
}
.hero-icon-wrap { position: relative; flex-shrink: 0; }
.hero-icon      { width: 54px; height: 54px; border-radius: 14px; object-fit: cover; }
.hero-ring      {
  position: absolute; inset: -5px; border-radius: 19px;
  border: 2px solid rgba(0,139,71,0.25);
  animation: pulse-green 3s ease-in-out infinite;
}
.hero-badge-row { margin-bottom: 5px; }
.hero-title     { font-size: 17px; font-weight: 700; margin-bottom: 5px; }
.hero-sub       { font-size: 11px; color: var(--text-2); font-weight: 400; }

/* KPIs */
.kpi-row { display: grid; grid-template-columns: repeat(4,1fr); gap: 12px; margin-bottom: 12px; }
.kpi-card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius-lg); padding: 14px 14px;
  display: flex; flex-direction: column; gap: 3px;
}
.kpi-label { font-size: 10px; font-weight: 500; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.07em; }
.kpi-val   { font-size: 28px; font-weight: 800; color: var(--text); line-height: 1; font-variant-numeric: tabular-nums; }
.kpi-val.green    { color: var(--green); }
.kpi-val.danger   { color: var(--danger); }
.kpi-val.warn-val { color: var(--warn); }
.kpi-sub   { font-size: 10px; color: var(--text-3); font-weight: 300; }

/* Features */
.features-row { display: flex; gap: 10px; margin-bottom: 18px; }
.feat {
  flex: 1; background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 10px 12px;
  display: flex; align-items: center; gap: 8px;
}
.feat-dot  { width: 7px; height: 7px; border-radius: 50%; background: var(--border-2); flex-shrink: 0; }
.feat-dot.on { background: var(--green); }
.feat-label { flex: 1; font-size: 11px; font-weight: 500; color: var(--text-2); }
.feat-state { font-size: 10px; font-weight: 700; color: var(--text-3); letter-spacing: 0.04em; }
.feat-state.on { color: var(--green); }

/* Section head */
.section-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
.section-title { font-size: 12px; font-weight: 700; color: var(--text-2); text-transform: uppercase; letter-spacing: 0.06em; }

/* Threat mini list */
.threat-mini-list { display: flex; flex-direction: column; gap: 7px; margin-bottom: 2px; }
.threat-mini {
  display: flex; align-items: center; gap: 12px;
  padding: 10px 14px; background: var(--card);
  border: 1px solid var(--border); border-radius: var(--radius);
}
.threat-mini.infected { border-left: 3px solid var(--danger); }
.threat-mini-icon     { flex-shrink: 0; }
.threat-mini-info     { flex: 1; min-width: 0; }
.threat-mini-name     { display: block; font-size: 11px; font-weight: 600; margin-bottom: 2px; font-family: monospace; }
.threat-mini-path     { display: block; font-size: 10px; color: var(--text-3); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* Last scan card */
.last-scan-card { padding: 14px 16px; }
.last-scan-row  { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.last-scan-stats { display: flex; gap: 24px; }
.last-scan-stats > div { display: flex; flex-direction: column; }
.ls-num   { font-size: 18px; font-weight: 700; font-variant-numeric: tabular-nums; }
.ls-num.danger { color: var(--danger); }
.ls-label { font-size: 10px; color: var(--text-3); font-weight: 300; }
</style>
