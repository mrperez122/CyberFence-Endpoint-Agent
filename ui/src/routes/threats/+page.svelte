<!-- Threats view -->
<script lang="ts">
  import { onMount } from 'svelte';

  let threats: any[] = [];
  let loading = true;
  let filter = 'ALL'; // ALL | INFECTED | SUSPICIOUS

  onMount(async () => {
    try {
      if ((window as any).__TAURI_INTERNALS__) {
        const { invoke } = await import('@tauri-apps/api/core');
        threats = await invoke('get_threats');
      } else {
        // Mock
        threats = [
          { id:'t1', detectedAt: ago(27),  path:'C:\\Users\\Carlos\\Downloads\\crack_photoshop.exe', verdict:'INFECTED',   threatName:'Win.Trojan.Generic-9953295-0',  severity:'CRITICAL', actionTaken:'QUARANTINED', scanType:'FULL_SCAN' },
          { id:'t2', detectedAt: ago(27),  path:'C:\\Users\\Carlos\\Downloads\\keygen.dll',          verdict:'SUSPICIOUS', threatName:'Heuristics.Broken.Executable',   severity:'MEDIUM',   actionTaken:'LOGGED',      scanType:'FULL_SCAN' },
          { id:'t3', detectedAt: ago(55),  path:'C:\\Users\\Carlos\\Desktop\\invoice_doc.exe',       verdict:'INFECTED',   threatName:'Win.Malware.Emotet-9827123-1',   severity:'CRITICAL', actionTaken:'QUARANTINED', scanType:'ON_ACCESS' },
        ];
      }
    } finally {
      loading = false;
    }
  });

  function ago(h: number) { return new Date(Date.now() - h * 3600_000).toISOString(); }

  function formatDate(iso: string) {
    const d = new Date(iso);
    return d.toLocaleDateString('en-US', { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
  }

  function shortPath(p: string) {
    const parts = p.replace(/\\/g, '/').split('/');
    return parts.slice(-2).join('/');
  }

  $: filtered = filter === 'ALL' ? threats : threats.filter(t => t.verdict === filter);
</script>

<div class="page animate-in">
  <div class="page-header">
    <div>
      <h1 class="page-title">Threats</h1>
      <p class="page-sub">{threats.length} threat{threats.length !== 1 ? 's' : ''} detected total</p>
    </div>
    <div class="filter-tabs">
      {#each ['ALL','INFECTED','SUSPICIOUS'] as f}
        <button class="filter-tab" class:active={filter === f} on:click={() => filter = f}>{f}</button>
      {/each}
    </div>
  </div>

  {#if loading}
    <div class="loading-state">Loading threats...</div>
  {:else if filtered.length === 0}
    <div class="empty-state">
      <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="color:var(--cf-green-1);margin-bottom:12px">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>
      </svg>
      <p>No threats found</p>
      <p class="text-muted text-sm">Your system is clean</p>
    </div>
  {:else}
    <div class="threat-list">
      {#each filtered as threat (threat.id)}
        <div class="threat-card" class:infected={threat.verdict === 'INFECTED'} class:suspicious={threat.verdict === 'SUSPICIOUS'}>
          <div class="threat-icon">
            {#if threat.verdict === 'INFECTED'}
              <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="color:var(--cf-danger)">
                <path d="m10.29 3.86-8.17 14.17A2 2 0 0 0 3.86 21h16.28a2 2 0 0 0 1.74-2.97L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
            {:else}
              <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="color:var(--cf-warning)">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
            {/if}
          </div>
          <div class="threat-info">
            <div class="threat-name">{threat.threatName}</div>
            <div class="threat-path" title={threat.path}>{shortPath(threat.path)}</div>
            <div class="threat-meta">
              <span class="badge {threat.verdict === 'INFECTED' ? 'badge-danger' : 'badge-at-risk'}">{threat.verdict}</span>
              <span class="badge badge-muted">{threat.scanType.replace('_', ' ')}</span>
              <span class="text-faint text-xs">{formatDate(threat.detectedAt)}</span>
            </div>
          </div>
          <div class="threat-action">
            <span class="action-badge" class:quarantined={threat.actionTaken === 'QUARANTINED'}
                                       class:logged={threat.actionTaken === 'LOGGED'}>
              {threat.actionTaken}
            </span>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
.page { padding: 28px 32px; }
.page-header { display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:24px; }
.page-title  { font-size:22px; font-weight:700; color:var(--cf-text); margin-bottom:2px; }
.page-sub    { font-size:13px; color:var(--cf-text-2); font-weight:300; }

.filter-tabs { display:flex; gap:4px; }
.filter-tab {
  padding: 6px 14px;
  border-radius: var(--radius);
  border: 1px solid var(--cf-border);
  background: transparent;
  color: var(--cf-text-2);
  font-size: 12px;
  font-weight: 600;
  font-family: var(--cf-font);
  cursor: pointer;
  transition: all 0.15s;
}
.filter-tab:hover  { border-color:var(--cf-border-2); color:var(--cf-text); }
.filter-tab.active { background:rgba(171,229,81,0.12); border-color:rgba(171,229,81,0.3); color:var(--cf-green-1); }

.loading-state, .empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 300px;
  color: var(--cf-text-2);
  font-size: 14px;
  font-weight: 300;
}

.threat-list { display:flex; flex-direction:column; gap:10px; }

.threat-card {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 16px 18px;
  background: var(--cf-bg-card);
  border: 1px solid var(--cf-border);
  border-radius: var(--radius-lg);
  transition: border-color 0.15s;
}
.threat-card:hover         { border-color:var(--cf-border-2); }
.threat-card.infected      { border-left: 3px solid var(--cf-danger); }
.threat-card.suspicious    { border-left: 3px solid var(--cf-warning); }

.threat-icon { flex-shrink:0; }
.threat-info { flex:1; min-width:0; }
.threat-name { font-size:13px; font-weight:600; color:var(--cf-text); margin-bottom:3px; font-family:'Courier New',monospace; }
.threat-path { font-size:11px; color:var(--cf-text-3); margin-bottom:8px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.threat-meta { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }

.threat-action { flex-shrink:0; }
.action-badge {
  font-size:11px;
  font-weight:700;
  padding: 4px 10px;
  border-radius: 999px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.action-badge.quarantined { background:rgba(171,229,81,0.1);  color:var(--cf-green-1); border:1px solid rgba(171,229,81,0.2); }
.action-badge.logged      { background:rgba(91,184,255,0.1);  color:var(--cf-info);    border:1px solid rgba(91,184,255,0.2); }
</style>
