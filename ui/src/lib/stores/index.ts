/**
 * Global Svelte stores — single source of truth for all dashboard state.
 * All views subscribe to these stores via $store syntax.
 */
import { writable, derived, get } from 'svelte/store';
import type { AgentStatus, ScanHistoryEntry, ThreatEntry, ScanProgress } from '../types';
import { api } from '../api';

// ── Core stores ───────────────────────────────────────────────────────────────

export const status       = writable<AgentStatus | null>(null);
export const scanHistory  = writable<ScanHistoryEntry[]>([]);
export const threats      = writable<ThreatEntry[]>([]);
export const loading      = writable(false);
export const scanProgress = writable<ScanProgress | null>(null);
export const scanState    = writable<'idle' | 'running' | 'complete'>('idle');
export const lastError    = writable<string | null>(null);

// ── Derived stores ────────────────────────────────────────────────────────────

export const threatCount = derived(threats, $t => $t.length);

export const highSeverityThreats = derived(threats, $t =>
  $t.filter(t => t.severity === 'CRITICAL')
);

export const protectionStatus = derived(status, $s =>
  $s?.protectionStatus ?? 'DISABLED'
);

// ── Data loaders ──────────────────────────────────────────────────────────────

export async function loadAll() {
  loading.set(true);
  lastError.set(null);
  try {
    const [s, h, t] = await Promise.all([
      api.getStatus(),
      api.getScanHistory(10),
      api.getThreats(),
    ]);
    status.set(s);
    scanHistory.set(h);
    threats.set(t);
  } catch (e: any) {
    lastError.set(e?.message ?? 'Unknown error loading data');
    console.error('loadAll failed:', e);
  } finally {
    loading.set(false);
  }
}

export async function refreshStatus() {
  try {
    status.set(await api.getStatus());
  } catch {}
}

export async function dismissThreat(id: string) {
  try {
    await api.dismissThreat(id);
    threats.update($t => $t.filter(t => t.id !== id));
  } catch (e) {
    console.error('dismissThreat failed:', e);
  }
}

// ── Scan actions ──────────────────────────────────────────────────────────────

export async function startQuickScan(): Promise<void> {
  if (get(scanState) === 'running') return;

  scanState.set('running');
  scanProgress.set({ jobId: 'quick-' + Date.now(), totalFiles: 0, scannedFiles: 0, threatsFound: 0, currentFile: null, percent: 0 });

  try {
    await api.runQuickScan();
    // Simulate progress in dev mode (Phase 3: listen to scan_progress events)
    await simulateProgress(900, 3000);
    scanState.set('complete');
    await refreshStatus();
    await loadScanHistory();
  } catch (e: any) {
    lastError.set('Quick scan failed: ' + e?.message);
    scanState.set('idle');
  }
}

export async function startFullScan(): Promise<void> {
  if (get(scanState) === 'running') return;

  scanState.set('running');
  scanProgress.set({ jobId: 'full-' + Date.now(), totalFiles: 48000, scannedFiles: 0, threatsFound: 0, currentFile: null, percent: 0 });

  try {
    await api.runFullScan();
    await simulateProgress(48000, 8000);
    scanState.set('complete');
    await refreshStatus();
    await loadScanHistory();
  } catch (e: any) {
    lastError.set('Full scan failed: ' + e?.message);
    scanState.set('idle');
  }
}

export function resetScan() {
  scanState.set('idle');
  scanProgress.set(null);
}

async function loadScanHistory() {
  try {
    scanHistory.set(await api.getScanHistory(10));
  } catch {}
}

// Simulates scan progress for dev mode — Phase 3 replaces with real events
async function simulateProgress(totalFiles: number, durationMs: number) {
  const startTime = Date.now();
  const mockFiles = [
    'C:\\Users\\Carlos\\Downloads\\setup.exe',
    'C:\\Users\\Carlos\\Desktop\\notes.txt',
    'C:\\Windows\\System32\\notepad.exe',
    'C:\\Program Files\\Chrome\\chrome.exe',
  ];

  return new Promise<void>(resolve => {
    const interval = setInterval(() => {
      const elapsed  = Date.now() - startTime;
      const pct      = Math.min(Math.floor((elapsed / durationMs) * 100), 100);
      const scanned  = Math.floor((pct / 100) * totalFiles);

      scanProgress.update(p => p ? {
        ...p,
        totalFiles,
        scannedFiles: scanned,
        percent:      pct,
        currentFile:  mockFiles[Math.floor(Math.random() * mockFiles.length)],
      } : p);

      if (pct >= 100) {
        clearInterval(interval);
        resolve();
      }
    }, 120);
  });
}
