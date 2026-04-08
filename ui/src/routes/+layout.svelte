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

  <!-- ── Sidebar ────────────────────────────────────────────────────────────── -->
  <aside class="sidebar">

    <!-- Logo -->
    <div class="sidebar-logo">
      <img src="/assets/app-icon.jpg" alt="CyberFence" class="logo-icon" />
      <div class="logo-words">
        <span class="logo-cf"><span style="font-weight:300">Cyber</span><span style="font-weight:800">Fence</span></span>
        <span class="logo-sub">Endpoint Protection</span>
      </div>
    </div>

    <!-- Protection status pill -->
    <div class="status-pill"
      class:protected={$protectionStatus === 'PROTECTED'}
      class:at-risk={$protectionStatus === 'AT_RISK' || $protectionStatus === 'DISABLED'}>
      <span class="status-dot"></span>
      {$protectionStatus === 'PROTECTED' ? 'Protected' :
       $protectionStatus === 'AT_RISK'   ? 'At Risk'   : 'Initializing…'}
    </div>

    <!-- Nav links -->
    <nav class="nav">
      <a href="/" class="nav-item" class:active={active('/')}>
        <!-- Shield icon -->
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        Overview
      </a>

      <a href="/threats" class="nav-item" class:active={active('/threats')}>
        <!-- Warning triangle -->
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path d="m10.29 3.86-8.17 14.17A2 2 0 0 0 3.86 21h16.28a2 2 0 0 0 1.74-2.97L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        Threats
        {#if $threatCount > 0}
          <span class="nav-badge">{$threatCount}</span>
        {/if}
      </a>

      <a href="/scan" class="nav-item" class:active={active('/scan')}>
        <!-- Scan / search icon -->
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <circle cx="11" cy="11" r="8"/>
          <path d="m21 21-4.35-4.35"/>
        </svg>
        Scan
      </a>

      <a href="/history" class="nav-item" class:active={active('/history')}>
        <!-- Clock icon -->
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <circle cx="12" cy="12" r="10"/>
          <polyline points="12 6 12 12 16 14"/>
        </svg>
        History
      </a>

      <div class="nav-divider"></div>

      <a href="/settings" class="nav-item" class:active={active('/settings')}>
        <!-- Settings gear icon -->
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <circle cx="12" cy="12" r="3"/>
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
        </svg>
        Settings
      </a>
    </nav>

    <div class="sidebar-footer">
      <span class="text-faint text-xs">v{$status?.agentVersion ?? '0.1.0'}</span>
      <a href="https://cyberfenceplatform.com" class="text-faint text-xs footer-link" target="_blank">cyberfenceplatform.com</a>
    </div>
  </aside>

  <!-- ── Main ───────────────────────────────────────────────────────────────── -->
  <main class="main">
    <slot />
  </main>

</div>

<style>
.layout { display: flex; height: 100vh; overflow: hidden; background: var(--bg); }

/* ── Sidebar ──────────────────────────────────────────────────────────── */
.sidebar {
  width: var(--sidebar-w);
  min-width: var(--sidebar-w);
  background: var(--sidebar);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  box-shadow: 1px 0 0 var(--border);
}

.sidebar-logo {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px 16px 16px;
  border-bottom: 1px solid var(--border);
}

.logo-icon {
  width: 34px;
  height: 34px;
  border-radius: 9px;
  object-fit: cover;
  flex-shrink: 0;
  box-shadow: 0 1px 4px rgba(0,139,71,0.18);
}

.logo-words { display: flex; flex-direction: column; line-height: 1; }
.logo-cf  { font-size: 14px; color: var(--green); letter-spacing: -0.01em; }
.logo-sub {
  font-size: 9px;
  font-weight: 500;
  color: var(--text-3);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  margin-top: 3px;
}

/* Status pill */
.status-pill {
  display: flex;
  align-items: center;
  gap: 7px;
  margin: 12px 12px 6px;
  padding: 8px 12px;
  border-radius: var(--radius);
  font-size: 11px;
  font-weight: 600;
  transition: all 0.2s;
  letter-spacing: 0.01em;
}
.status-pill.protected {
  background: rgba(0,139,71,0.08);
  color: var(--green);
  border: 1px solid rgba(0,139,71,0.18);
}
.status-pill.at-risk {
  background: rgba(230,126,34,0.08);
  color: var(--warn);
  border: 1px solid rgba(230,126,34,0.18);
}
.status-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
  background: currentColor;
}
.status-pill.protected .status-dot { animation: pulse-green 2.5s infinite; }

/* Nav */
.nav {
  display: flex;
  flex-direction: column;
  gap: 1px;
  padding: 8px 8px;
  flex: 1;
  overflow-y: auto;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 10px;
  border-radius: var(--radius);
  color: var(--text-2);
  font-size: 13px;
  font-weight: 500;
  transition: all 0.15s;
  text-decoration: none;
  position: relative;
}
.nav-item:hover  { background: var(--green-lite); color: var(--text); }
.nav-item.active {
  background: rgba(0,139,71,0.1);
  color: var(--green);
  font-weight: 700;
}
.nav-item svg    { opacity: 0.65; flex-shrink: 0; }
.nav-item.active svg, .nav-item:hover svg { opacity: 1; }

.nav-badge {
  margin-left: auto;
  background: var(--danger);
  color: white;
  font-size: 10px;
  font-weight: 700;
  padding: 1px 6px;
  border-radius: 999px;
  min-width: 18px;
  text-align: center;
}

.nav-divider {
  height: 1px;
  background: var(--border);
  margin: 6px 4px;
}

.sidebar-footer {
  padding: 12px 16px;
  border-top: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.footer-link { text-decoration: none; }
.footer-link:hover { color: var(--green); }

/* ── Main ──────────────────────────────────────────────────────────────── */
.main { flex: 1; overflow-y: auto; background: var(--bg); }
</style>
