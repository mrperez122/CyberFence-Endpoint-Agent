<script lang="ts">
  import { threats, dismissThreat } from '$lib/stores';
  let filter = 'ALL';

  $: filtered = filter === 'ALL' ? $threats
    : $threats.filter(t => t.verdict === filter);

  function shortPath(p: string) {
    return p.replace(/\\/g, '/').split('/').slice(-2).join('/');
  }

  function relTime(iso: string) {
    const h = Math.floor((Date.now() - new Date(iso).getTime()) / 3_600_000);
    return h < 1 ? 'Just now' : h < 24 ? `${h}h ago` : `${Math.floor(h/24)}d ago`;
  }

  function fmtSize(b: number | null) {
    if (!b) return null;
    return b > 1_048_576 ? (b/1_048_576).toFixed(1)+' MB' : (b/1024).toFixed(0)+' KB';
  }
</script>

<div class="page animate-in">
  <div class="page-header">
    <div>
      <h1 class="page-title">Threats</h1>
      <p class="page-sub">{$threats.length} threat{$threats.length !== 1 ? 's' : ''} detected</p>
    </div>
    <div class="filter-tabs">
      {#each ['ALL','INFECTED','SUSPICIOUS'] as f}
        <button class="ftab" class:active={filter === f} on:click={() => filter = f}>{f}</button>
      {/each}
    </div>
  </div>

  {#if filtered.length === 0}
    <div class="empty">
      <svg width="44" height="44" fill="none" stroke="var(--green)" stroke-width="1.5" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
      <p>No threats found</p>
      <p class="text-faint text-sm">Your system is clean</p>
    </div>
  {:else}
    <div class="threat-list">
      {#each filtered as t (t.id)}
        <div class="threat-card" class:infected={t.verdict==='INFECTED'} class:suspicious={t.verdict==='SUSPICIOUS'}>
          <div class="tc-icon">
            {#if t.verdict === 'INFECTED'}
              <svg width="20" height="20" fill="none" stroke="var(--danger)" stroke-width="2" viewBox="0 0 24 24"><path d="m10.29 3.86-8.17 14.17A2 2 0 0 0 3.86 21h16.28a2 2 0 0 0 1.74-2.97L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            {:else}
              <svg width="20" height="20" fill="none" stroke="var(--warn)" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            {/if}
          </div>

          <div class="tc-info">
            <div class="tc-name">{t.threatName}</div>
            <div class="tc-path" title={t.path}>{shortPath(t.path)}</div>
            <div class="tc-meta">
              <span class="badge {t.verdict==='INFECTED' ? 'badge-danger' : 'badge-warn'}">{t.verdict}</span>
              <span class="badge badge-muted">.{t.extension}</span>
              {#if fmtSize(t.sizeBytes)}<span class="badge badge-muted">{fmtSize(t.sizeBytes)}</span>{/if}
              <span class="badge badge-muted">{t.scanType.replace('_',' ')}</span>
              <span class="text-faint text-xs">{relTime(t.detectedAt)}</span>
            </div>
          </div>

          <div class="tc-actions">
            <span class="badge {t.actionTaken==='QUARANTINED' ? 'badge-quarantined' : 'badge-info'}">{t.actionTaken}</span>
            <button class="btn btn-ghost text-xs" on:click={() => dismissThreat(t.id)}>Dismiss</button>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
.page        { padding: 24px 28px; }
.page-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 20px; }
.page-title  { font-size: 20px; font-weight: 700; margin-bottom: 1px; }
.page-sub    { font-size: 12px; color: var(--text-2); font-weight: 300; }

.filter-tabs { display: flex; gap: 4px; }
.ftab {
  padding: 5px 13px; border-radius: var(--radius);
  border: 1px solid var(--border); background: transparent;
  color: var(--text-2); font-size: 11px; font-weight: 600;
  font-family: var(--font); cursor: pointer; transition: all 0.15s;
}
.ftab:hover  { border-color: var(--border-2); color: var(--text); }
.ftab.active { background: rgba(0,139,71,0.1); border-color: rgba(0,139,71,0.3); color: var(--green); }

.empty {
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  height: 280px; gap: 8px; color: var(--text-2);
}

.threat-list { display: flex; flex-direction: column; gap: 9px; }
.threat-card {
  display: flex; align-items: center; gap: 14px;
  padding: 14px 16px; background: var(--card);
  border: 1px solid var(--border); border-radius: var(--radius-lg);
  transition: border-color 0.15s;
}
.threat-card:hover       { border-color: var(--border-2); }
.threat-card.infected    { border-left: 3px solid var(--danger); }
.threat-card.suspicious  { border-left: 3px solid var(--warn); }

.tc-icon  { flex-shrink: 0; }
.tc-info  { flex: 1; min-width: 0; }
.tc-name  { font-size: 12px; font-weight: 600; margin-bottom: 3px; font-family: monospace; }
.tc-path  { font-size: 10px; color: var(--text-3); margin-bottom: 7px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tc-meta  { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.tc-actions { display: flex; flex-direction: column; align-items: flex-end; gap: 6px; flex-shrink: 0; }
</style>
