<script lang="ts">
  import '../app.css';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { loadAll, status, threatCount, protectionStatus } from '$lib/stores';

  onMount(() => {
    loadAll();
    const iv = setInterval(loadAll, 30_000);
    return () => clearInterval(iv);
  });

  $: active = (path: string) =>
    path === '/' ? $page.url.pathname === '/' : $page.url.pathname.startsWith(path);
</script>

<div class="layout">

  <!-- ── Sidebar ───────────────────────────────────────────────────────────── -->
  <aside class="sidebar">

    <!-- Logo -->
    <div class="sidebar-logo">
      <img src="/assets/app-icon.jpg" alt="CyberFence" class="logo-icon" />
      <div class="logo-words">
        <span class="logo-cf"><span style="font-weight:300">Cyber</span><span style="font-weight:800">Fence</span></span>
        <span class="logo-sub">Endpoint</span>
      </div>
    </div>

    <!-- Protection status pill -->
    <div class="status-pill" class:protected={$protectionStatus === 'PROTECTED'}
                             class:at-risk={$protectionStatus === 'AT_RISK' || $protectionStatus === 'DISABLED'}>
      <span class="status-dot"></span>
      {$protectionStatus === 'PROTECTED' ? 'Protected' :
       $protectionStatus === 'AT_RISK'   ? 'At Risk'   : 'Disabled'}
    </div>

    <!-- Nav links -->
    <nav class="nav">
      <a href="/"          class="nav-item" class:active={active('/')}>
        <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Overview
      </a>
      <a href="/threats"   class="nav-item" class:active={active('/threats')}>
        <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="m10.29 3.86-8.17 14.17A2 2 0 0 0 3.86 21h16.28a2 2 0 0 0 1.74-2.97L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        Threats
        {#if $threatCount > 0}
          <span class="nav-badge">{$threatCount}</span>
        {/if}
      </a>
      <a href="/scan"      class="nav-item" class:active={active('/scan')}>
        <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        Scan
      </a>
      <a href="/history"   class="nav-item" class:active={active('/history')}>
        <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        History
      </a>
    </nav>

    <div class="sidebar-footer">
      <span class="text-faint text-xs">v{$status?.agentVersion ?? '0.1.0'}</span>
      <span class="text-faint text-xs">CyberFence EP</span>
    </div>
  </aside>

  <!-- ── Main ───────────────────────────────────────────────────────────────── -->
  <main class="main">
    <slot />
  </main>

</div>

<style>
.layout { display: flex; height: 100vh; overflow: hidden; }

/* ── Sidebar ─────────────────────────────────────────────────────────── */
.sidebar {
  width: var(--sidebar-w);
  min-width: var(--sidebar-w);
  background: var(--sidebar);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.sidebar-logo {
  display: flex; align-items: center; gap: 10px;
  padding: 18px 16px 14px;
  border-bottom: 1px solid var(--border);
}

.logo-icon { width: 30px; height: 30px; border-radius: 8px; object-fit: cover; flex-shrink: 0; }
.logo-words { display: flex; flex-direction: column; line-height: 1; }
.logo-cf  { font-size: 13px; color: var(--green); }
.logo-sub { font-size: 9px; font-weight: 500; color: var(--text-3); letter-spacing: 0.1em; text-transform: uppercase; margin-top: 2px; }

/* Status pill */
.status-pill {
  display: flex; align-items: center; gap: 7px;
  margin: 12px 10px 6px;
  padding: 7px 11px;
  border-radius: var(--radius);
  font-size: 11px; font-weight: 600;
  transition: all 0.2s;
}
.status-pill.protected { background: rgba(0,139,71,0.1); color: var(--green); border: 1px solid rgba(0,139,71,0.2); }
.status-pill.at-risk   { background: rgba(230,126,34,0.1); color: var(--warn); border: 1px solid rgba(230,126,34,0.2); }

.status-dot {
  width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0;
  background: currentColor;
}
.status-pill.protected .status-dot { animation: pulse-green 2.5s infinite; }

/* Nav */
.nav { display: flex; flex-direction: column; gap: 2px; padding: 8px; flex: 1; }

.nav-item {
  display: flex; align-items: center; gap: 9px;
  padding: 9px 10px; border-radius: var(--radius);
  color: var(--text-2); font-size: 13px; font-weight: 500;
  transition: all 0.15s; text-decoration: none; position: relative;
}
.nav-item:hover  { background: var(--green-lite); color: var(--text); }
.nav-item.active { background: rgba(0,139,71,0.1); color: var(--green); font-weight: 700; }
.nav-item svg    { opacity: 0.7; flex-shrink: 0; }
.nav-item.active svg, .nav-item:hover svg { opacity: 1; }

.nav-badge {
  margin-left: auto;
  background: var(--danger); color: white;
  font-size: 10px; font-weight: 700;
  padding: 1px 5px; border-radius: 999px;
}

.sidebar-footer {
  padding: 12px 16px;
  border-top: 1px solid var(--border);
  display: flex; justify-content: space-between;
}

/* ── Main ────────────────────────────────────────────────────────────── */
.main { flex: 1; overflow-y: auto; background: var(--bg); }
</style>
