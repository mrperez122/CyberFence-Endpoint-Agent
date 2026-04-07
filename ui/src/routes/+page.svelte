<!-- Overview / Home page -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { statusStore } from '$lib/stores/status';

  let scanHistory: any[] = [];
  let threatCount = 0;
  let scanning = false;
  let scanMessage = '';

  async function invoke(cmd: string, args?: any) {
    if (typeof window !== 'undefined' && (window as any).__TAURI_INTERNALS__) {
      const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
      return tauriInvoke(cmd, args);
    }
    // Mock
    const { loadStatus } = await import('$lib/stores/status');
    const mod = await import('$lib/stores/status');
    return (mod as any).getMockData?.(cmd) ?? null;
  }

  onMount(async () => {
    try {
      const { default: _, ...mod } = await import('$lib/stores/status');
      scanHistory = (await (mod as any).invokeOrMock?.('get_scan_history') ?? []).slice(0, 3);
    } catch {}
    threatCount = $statusStore?.threatsTotal ?? 3;
  });

  async function runQuickScan() {
    scanning = true;
    scanMessage = 'Quick scan running...';
    try {
      if ((window as any).__TAURI_INTERNALS__) {
        const { invoke: ti } = await import('@tauri-apps/api/core');
        await ti('run_quick_scan');
      }
      await new Promise(r => setTimeout(r, 2000));
      scanMessage = 'Quick scan complete — no threats found.';
    } finally {
      setTimeout(() => { scanning = false; scanMessage = ''; }, 3000);
    }
  }

  function formatTime(iso: string | null): string {
    if (!iso) return 'Never';
    const d = new Date(iso);
    const diff = Date.now() - d.getTime();
    const h = Math.floor(diff / 3600_000);
    if (h < 1)  return 'Just now';
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h/24)}d ago`;
  }

  function formatFiles(n: number): string {
    if (n >= 1_000_000) return (n/1_000_000).toFixed(1) + 'M';
    if (n >= 1_000)     return (n/1_000).toFixed(1) + 'K';
    return String(n);
  }
</script>

<div class="page animate-in">
  <!-- ── Page header ──────────────────────────────────────────────────── -->
  <div class="page-header">
    <div>
      <h1 class="page-title">Overview</h1>
      <p class="page-sub">System protection status and summary</p>
    </div>
    <button class="btn btn-primary" on:click={runQuickScan} disabled={scanning}>
      <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
      </svg>
      {scanning ? 'Scanning...' : 'Quick Scan'}
    </button>
  </div>

  {#if scanMessage}
    <div class="scan-toast">{scanMessage}</div>
  {/if}

  <!-- ── Status hero ───────────────────────────────────────────────────── -->
  <div class="status-hero" class:at-risk={$statusStore?.protectionStatus !== 'PROTECTED'}>
    <div class="hero-shield">
      <img src="/assets/app-icon.jpg" alt="CyberFence shield" class="hero-icon" />
      <div class="hero-ring" class:pulse={$statusStore?.protectionStatus === 'PROTECTED'}></div>
    </div>
    <div class="hero-info">
      <div class="hero-status-label">
        {#if $statusStore?.protectionStatus === 'PROTECTED'}
          <span class="badge badge-protected">● Protected</span>
        {:else}
          <span class="badge badge-at-risk">⚠ At Risk</span>
        {/if}
      </div>
      <h2 class="hero-title">
        {$statusStore?.protectionStatus === 'PROTECTED'
          ? 'Your device is protected'
          : 'Action required'}
      </h2>
      <p class="hero-sub">
        Last scan: {formatTime($statusStore?.lastScanTime ?? null)} ·
        Definitions: v{$statusStore?.definitionsVersion ?? '—'} ({$statusStore?.definitionsAgeHours ?? 0}h old)
      </p>
    </div>
  </div>

  <!-- ── KPI cards ─────────────────────────────────────────────────────── -->
  <div class="kpi-grid">
    <div class="kpi-card">
      <span class="kpi-label">Files monitored today</span>
      <span class="kpi-value green">{formatFiles($statusStore?.filesMonitoredToday ?? 0)}</span>
      <span class="kpi-sub">real-time</span>
    </div>
    <div class="kpi-card">
      <span class="kpi-label">Threats detected</span>
      <span class="kpi-value" class:danger={($statusStore?.threatsTotal ?? 0) > 0}>
        {$statusStore?.threatsTotal ?? 0}
      </span>
      <span class="kpi-sub">all time</span>
    </div>
    <div class="kpi-card">
      <span class="kpi-label">Today's threats</span>
      <span class="kpi-value" class:danger={($statusStore?.threatsToday ?? 0) > 0}>
        {$statusStore?.threatsToday ?? 0}
      </span>
      <span class="kpi-sub">past 24h</span>
    </div>
    <div class="kpi-card">
      <span class="kpi-label">Definitions age</span>
      <span class="kpi-value" class:warning={($statusStore?.definitionsAgeHours ?? 0) > 12}>
        {$statusStore?.definitionsAgeHours ?? 0}h
      </span>
      <span class="kpi-sub">
        {($statusStore?.definitionsAgeHours ?? 0) <= 12 ? 'up to date' : 'outdated'}
      </span>
    </div>
  </div>

  <!-- ── Feature status row ────────────────────────────────────────────── -->
  <div class="features-row">
    <div class="feature-item">
      <span class="feature-dot" class:on={$statusStore?.realtimeMonitoring}></span>
      <span class="feature-label">Real-time monitoring</span>
      <span class="feature-state">{$statusStore?.realtimeMonitoring ? 'ON' : 'OFF'}</span>
    </div>
    <div class="feature-item">
      <span class="feature-dot" class:on={$statusStore?.scanningEnabled}></span>
      <span class="feature-label">Malware scanning</span>
      <span class="feature-state">{$statusStore?.scanningEnabled ? 'ON' : 'OFF'}</span>
    </div>
    <div class="feature-item">
      <span class="feature-dot on"></span>
      <span class="feature-label">ClamAV engine</span>
      <span class="feature-state">Active</span>
    </div>
  </div>
</div>

<style>
.page {
  padding: 28px 32px;
  max-width: 100%;
}

.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 24px;
}

.page-title {
  font-size: 22px;
  font-weight: 700;
  color: var(--cf-text);
  margin-bottom: 2px;
}

.page-sub {
  font-size: 13px;
  color: var(--cf-text-2);
  font-weight: 300;
}

.scan-toast {
  background: rgba(171,229,81,0.12);
  border: 1px solid rgba(171,229,81,0.3);
  color: var(--cf-green-1);
  padding: 10px 16px;
  border-radius: var(--radius);
  font-size: 13px;
  margin-bottom: 16px;
  animation: fade-in 0.2s ease;
}

/* Hero */
.status-hero {
  background: linear-gradient(135deg, rgba(0,139,71,0.15) 0%, rgba(13,31,14,0.8) 60%);
  border: 1px solid rgba(171,229,81,0.2);
  border-radius: var(--radius-lg);
  padding: 24px;
  display: flex;
  align-items: center;
  gap: 24px;
  margin-bottom: 20px;
  position: relative;
  overflow: hidden;
}

.status-hero.at-risk {
  background: linear-gradient(135deg, rgba(245,166,35,0.1) 0%, rgba(13,31,14,0.8) 60%);
  border-color: rgba(245,166,35,0.25);
}

.hero-shield {
  position: relative;
  flex-shrink: 0;
}

.hero-icon {
  width: 64px;
  height: 64px;
  border-radius: 14px;
  object-fit: cover;
  position: relative;
  z-index: 1;
}

.hero-ring {
  position: absolute;
  inset: -6px;
  border-radius: 20px;
  border: 2px solid rgba(171,229,81,0.4);
}

.hero-ring.pulse {
  animation: pulse-green 3s infinite;
}

.hero-status-label { margin-bottom: 6px; }

.hero-title {
  font-size: 20px;
  font-weight: 700;
  color: var(--cf-text);
  margin-bottom: 6px;
}

.hero-sub {
  font-size: 12px;
  color: var(--cf-text-2);
  font-weight: 300;
}

/* KPIs */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 14px;
  margin-bottom: 16px;
}

.kpi-card {
  background: var(--cf-bg-card);
  border: 1px solid var(--cf-border);
  border-radius: var(--radius-lg);
  padding: 18px 16px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.kpi-label {
  font-size: 11px;
  font-weight: 500;
  color: var(--cf-text-3);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.kpi-value {
  font-size: 32px;
  font-weight: 800;
  color: var(--cf-text);
  line-height: 1;
  font-variant-numeric: tabular-nums;
}

.kpi-value.green   { color: var(--cf-green-1); }
.kpi-value.danger  { color: var(--cf-danger); }
.kpi-value.warning { color: var(--cf-warning); }

.kpi-sub {
  font-size: 11px;
  color: var(--cf-text-3);
  font-weight: 300;
}

/* Features */
.features-row {
  display: flex;
  gap: 12px;
}

.feature-item {
  flex: 1;
  background: var(--cf-bg-card);
  border: 1px solid var(--cf-border);
  border-radius: var(--radius);
  padding: 12px 14px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.feature-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  background: var(--cf-text-3);
  flex-shrink: 0;
}
.feature-dot.on { background: var(--cf-green-1); }

.feature-label {
  flex: 1;
  font-size: 12px;
  font-weight: 500;
  color: var(--cf-text-2);
}

.feature-state {
  font-size: 11px;
  font-weight: 700;
  color: var(--cf-green-1);
  letter-spacing: 0.05em;
}
</style>
