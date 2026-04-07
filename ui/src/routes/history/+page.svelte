<script lang="ts">
  import { scanHistory } from '$lib/stores';

  function relTime(iso: string) {
    const d = new Date(iso);
    const now = new Date();
    const diffMs = now.getTime() - d.getTime();
    const h = Math.floor(diffMs / 3_600_000);
    if (h < 1)  return 'Just now';
    if (h < 24) return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) + ' today';
    if (h < 48) return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) + ' yesterday';
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  function fmtDur(s: number) {
    return s < 60 ? `${s}s` : `${Math.floor(s/60)}m ${s%60}s`;
  }
  function fmtFiles(n: number) {
    return n >= 1000 ? (n/1000).toFixed(1)+'K' : String(n);
  }
</script>

<div class="page animate-in">
  <div class="page-header">
    <div>
      <h1 class="page-title">Scan History</h1>
      <p class="page-sub">{$scanHistory.length} scan{$scanHistory.length !== 1 ? 's' : ''} recorded</p>
    </div>
  </div>

  <div class="table-wrap card">
    <table>
      <thead>
        <tr>
          <th>Type</th>
          <th>Started</th>
          <th>Duration</th>
          <th>Files</th>
          <th>Threats</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {#each $scanHistory as entry (entry.id)}
          <tr class:has-threats={entry.threatsFound > 0}>
            <td>
              <span class="badge {entry.scanType === 'FULL_SCAN' ? 'badge-info' : 'badge-muted'}">
                {entry.scanType.replace('_',' ')}
              </span>
            </td>
            <td class="dim">{relTime(entry.startedAt)}</td>
            <td class="mono">{fmtDur(entry.durationSecs)}</td>
            <td class="mono">{fmtFiles(entry.filesScanned)}</td>
            <td>
              {#if entry.threatsFound > 0}
                <span class="tcount">{entry.threatsFound} threat{entry.threatsFound > 1 ? 's' : ''}</span>
              {:else}
                <span class="dim">None</span>
              {/if}
            </td>
            <td><span class="badge badge-protected">{entry.status}</span></td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>

<style>
.page        { padding: 24px 28px; }
.page-header { margin-bottom: 20px; }
.page-title  { font-size: 20px; font-weight: 700; margin-bottom: 1px; }
.page-sub    { font-size: 12px; color: var(--text-2); font-weight: 300; }

.table-wrap  { padding: 0; overflow: hidden; }

table { width: 100%; border-collapse: collapse; font-size: 12px; }

thead tr { background: rgba(0,139,71,0.04); border-bottom: 1px solid var(--border); }
th {
  padding: 10px 14px; text-align: left;
  font-size: 10px; font-weight: 700; color: var(--text-3);
  text-transform: uppercase; letter-spacing: 0.07em;
}

td {
  padding: 13px 14px;
  border-bottom: 1px solid var(--border);
  color: var(--text);
}
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover td      { background: rgba(0,0,0,0.02); }
tbody tr.has-threats td { background: rgba(217,48,37,0.03); }

.dim   { color: var(--text-2); }
.mono  { font-family: monospace; font-variant-numeric: tabular-nums; }
.tcount { color: var(--danger); font-weight: 700; }
</style>
