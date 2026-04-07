<script lang="ts">
  import '../app.css';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { statusStore, loadStatus } from '$lib/stores/status';

  // Load status on mount and refresh every 30s
  onMount(() => {
    loadStatus();
    const interval = setInterval(loadStatus, 30_000);
    return () => clearInterval(interval);
  });

  const navItems = [
    { path: '/',          label: 'Overview',  icon: ShieldIcon  },
    { path: '/threats',   label: 'Threats',   icon: AlertIcon   },
    { path: '/scan',      label: 'Scan',      icon: ScanIcon    },
    { path: '/history',   label: 'History',   icon: HistoryIcon },
    { path: '/settings',  label: 'Settings',  icon: GearIcon    },
  ];

  $: currentPath = $page.url.pathname;

  function isActive(path: string): boolean {
    if (path === '/') return currentPath === '/';
    return currentPath.startsWith(path);
  }

  // Inline SVG icons (no external deps)
  const ShieldIcon  = `<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
  const AlertIcon   = `<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="m10.29 3.86-8.17 14.17A2 2 0 0 0 3.86 21h16.28a2 2 0 0 0 1.74-2.97L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  const ScanIcon    = `<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>`;
  const HistoryIcon = `<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`;
  const GearIcon    = `<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`;
</script>

<div class="layout">
  <!-- ── Sidebar ──────────────────────────────────────────────────────── -->
  <aside class="sidebar">
    <!-- Logo -->
    <div class="sidebar-logo">
      <img src="/assets/app-icon.jpg" alt="CyberFence icon" class="logo-icon" />
      <div class="logo-text">
        <span class="logo-cyber">Cyber</span><span class="logo-fence">Fence</span>
        <span class="logo-sub">Endpoint</span>
      </div>
    </div>

    <!-- Status pill -->
    <div class="status-pill" class:protected={$statusStore?.protectionStatus === 'PROTECTED'}
                             class:at-risk={$statusStore?.protectionStatus !== 'PROTECTED'}>
      <span class="status-dot"></span>
      {$statusStore?.protectionStatus === 'PROTECTED' ? 'Protected' : 'At Risk'}
    </div>

    <!-- Nav -->
    <nav class="nav">
      {#each navItems as item}
        <a href={item.path}
           class="nav-item"
           class:active={isActive(item.path)}>
          <span class="nav-icon">{@html item.icon}</span>
          <span class="nav-label">{item.label}</span>
          {#if item.path === '/threats' && ($statusStore?.threatsTotal ?? 0) > 0}
            <span class="nav-badge">{$statusStore?.threatsTotal}</span>
          {/if}
        </a>
      {/each}
    </nav>

    <!-- Version footer -->
    <div class="sidebar-footer">
      <span class="text-faint text-xs">v{$statusStore?.agentVersion ?? '0.1.0'}</span>
      <span class="text-faint text-xs">CyberFence EP</span>
    </div>
  </aside>

  <!-- ── Main content ─────────────────────────────────────────────────── -->
  <main class="main">
    <slot />
  </main>
</div>

<style>
.layout {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

/* ── Sidebar ───────────────────────────────────────────── */
.sidebar {
  width: var(--sidebar-w);
  min-width: var(--sidebar-w);
  background: #0a160b;
  border-right: 1px solid var(--cf-border);
  display: flex;
  flex-direction: column;
  gap: 0;
  padding: 0;
  overflow: hidden;
}

.sidebar-logo {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 18px 16px 14px;
  border-bottom: 1px solid var(--cf-border);
}

.logo-icon {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  object-fit: cover;
  flex-shrink: 0;
}

.logo-text {
  display: flex;
  flex-direction: column;
  line-height: 1;
}

.logo-cyber  { font-size: 13px; font-weight: 300; color: var(--cf-green-1); }
.logo-fence  { font-size: 13px; font-weight: 800; color: var(--cf-green-1); display: inline; }
.logo-sub    { font-size: 9px;  font-weight: 500; color: var(--cf-text-3); letter-spacing: 0.1em; text-transform: uppercase; margin-top: 2px; }

.status-pill {
  display: flex;
  align-items: center;
  gap: 7px;
  margin: 12px 12px 8px;
  padding: 7px 12px;
  border-radius: var(--radius);
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.03em;
  transition: all 0.2s;
}

.status-pill.protected {
  background: rgba(171,229,81,0.12);
  color: var(--cf-green-1);
  border: 1px solid rgba(171,229,81,0.2);
}

.status-pill.at-risk {
  background: rgba(245,166,35,0.12);
  color: var(--cf-warning);
  border: 1px solid rgba(245,166,35,0.2);
}

.status-dot {
  width: 7px; height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
}

.status-pill.protected .status-dot {
  background: var(--cf-green-1);
  animation: pulse-green 2.5s infinite;
}

.status-pill.at-risk .status-dot {
  background: var(--cf-warning);
}

/* ── Nav ───────────────────────────────────────────────── */
.nav {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 8px 8px;
  flex: 1;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 10px;
  border-radius: var(--radius);
  color: var(--cf-text-2);
  font-size: 13px;
  font-weight: 500;
  transition: all 0.15s ease;
  position: relative;
  text-decoration: none;
}

.nav-item:hover {
  background: rgba(171,229,81,0.07);
  color: var(--cf-text);
}

.nav-item.active {
  background: rgba(171,229,81,0.13);
  color: var(--cf-green-1);
  font-weight: 600;
}

.nav-item.active .nav-icon {
  color: var(--cf-green-1);
}

.nav-icon {
  display: flex;
  align-items: center;
  flex-shrink: 0;
  opacity: 0.75;
}

.nav-item.active .nav-icon { opacity: 1; }
.nav-item:hover  .nav-icon { opacity: 1; }

.nav-label { flex: 1; }

.nav-badge {
  background: var(--cf-danger);
  color: white;
  font-size: 10px;
  font-weight: 700;
  padding: 1px 5px;
  border-radius: 999px;
  min-width: 18px;
  text-align: center;
}

.sidebar-footer {
  padding: 12px 16px;
  border-top: 1px solid var(--cf-border);
  display: flex;
  justify-content: space-between;
}

/* ── Main ──────────────────────────────────────────────── */
.main {
  flex: 1;
  overflow-y: auto;
  background: var(--cf-bg);
}
</style>
