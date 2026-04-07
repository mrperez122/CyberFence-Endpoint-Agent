<!-- Scan history view -->
<script lang="ts">
  import { onMount } from 'svelte';

  let history: any[] = [];
  let loading = true;

  function ago(h: number) { return new Date(Date.now() - h * 3600_000).toISOString(); }

  onMount(async () => {
    try {
      if ((window as any).__TAURI_INTERNALS__) {
        const { invoke } = await import('@tauri-apps/api/core');
        history = await invoke('get_scan_history', { limit: 20 });
      } else {
        history = [
          { id:'s1', scanType:'QUICK_SCAN', startedAt:ago(2),   completedAt:ago(1.95), filesScanned:847,   threatsFound:0, durationSecs:183,  status:'COMPLETE' },
          { id:'s2', scanType:'FULL_SCAN',  startedAt:ago(26),  completedAt:ago(25.6), filesScanned:48391, threatsFound:2, durationSecs:1340, status:'COMPLETE' },
          { id:'s3', scanType:'QUICK_SCAN', startedAt:ago(50),  completedAt:ago(49.9), filesScanned:912,   threatsFound:1, durationSecs:241,  status:'COMPLETE' },
          { id:'s4', scanType:'FULL_SCAN',  startedAt:ago(170), completedAt:ago(169.7),filesScanned:47102, threatsFound:0, durationSecs:1148, status:'COMPLETE' },
        ];
      }
    } finally { loading = false; }
  });

  function formatDate(iso: string) {
    return new Date(iso).toLocaleDateString('en-US', { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
  }

  function formatDur(s: number) {
    if (s < 60) return `${s}s`;
    return `${Math.floor(s/60)}m ${s%60}s`;
  }

  function formatFiles(n: number) {
    return n >= 1000 ? (n/1000).toFixed(1)+'K' : String(n);
  }

  function scanTypeLabel(t: string) {
    return t.replace('_', ' ');
  }
</script>

<div class="page animate-in">
  <div class="page-header">
    <div>
      <h1 class="page-title">Scan History</h1>
      <p class="page-sub">{history.length} scans recorded</p>
    </div>
  </div>

  {#if loading}
    <div class="loading-state">Loading history...</div>
  {:else}
    <div class="history-table-wrap card">
      <table class="history-table">
        <thead>
          <tr>
            <th>Type</th>
            <th>Started</th>
            <th>Duration</th>
            <th>Files Scanned</th>
            <th>Threats</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {#each history as entry (entry.id)}
            <tr class:has-threats={entry.threatsFound > 0}>
              <td>
                <span class="badge {entry.scanType === 'FULL_SCAN' ? 'badge-info' : 'badge-muted'}">
                  {scanTypeLabel(entry.scanType)}
                </span>
              </td>
              <td class="text-muted">{formatDate(entry.startedAt)}</td>
              <td class="mono">{formatDur(entry.durationSecs)}</td>
              <td class="mono">{formatFiles(entry.filesScanned)}</td>
              <td>
                {#if entry.threatsFound > 0}
                  <span class="threat-count">{entry.threatsFound} threat{entry.threatsFound > 1 ? 's' : ''}</span>
                {:else}
                  <span class="text-faint">None</span>
                {/if}
              </td>
              <td>
                <span class="badge badge-protected">{entry.status}</span>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<style>
.page { padding:28px 32px; }
.page-header { display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:24px; }
.page-title  { font-size:22px; font-weight:700; margin-bottom:2px; }
.page-sub    { font-size:13px; color:var(--cf-text-2); font-weight:300; }

.loading-state { display:flex; align-items:center; justify-content:center; height:200px; color:var(--cf-text-2); }

.history-table-wrap { padding:0; overflow:hidden; }

.history-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

.history-table thead tr {
  background: rgba(171,229,81,0.04);
  border-bottom: 1px solid var(--cf-border);
}

.history-table th {
  padding: 12px 16px;
  text-align: left;
  font-size: 11px;
  font-weight: 700;
  color: var(--cf-text-3);
  text-transform: uppercase;
  letter-spacing: 0.07em;
}

.history-table td {
  padding: 14px 16px;
  border-bottom: 1px solid var(--cf-border);
  color: var(--cf-text);
}

.history-table tbody tr:last-child td { border-bottom: none; }
.history-table tbody tr:hover td { background: rgba(255,255,255,0.02); }
.history-table tbody tr.has-threats td { background: rgba(224,82,82,0.04); }

.text-muted { color: var(--cf-text-2); }
.text-faint { color: var(--cf-text-3); }
.mono       { font-variant-numeric: tabular-nums; font-family: 'Courier New', monospace; }

.threat-count {
  color: var(--cf-danger);
  font-weight: 700;
  font-size: 12px;
}
</style>
