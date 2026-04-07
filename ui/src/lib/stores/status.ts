/**
 * Global status store — shared across all views.
 * Loads from Tauri IPC (or mock data in browser/dev mode).
 */
import { writable } from 'svelte/store';

export interface AgentStatus {
  protectionStatus:   'PROTECTED' | 'AT_RISK' | 'SCANNING' | 'DISABLED';
  realtimeMonitoring: boolean;
  scanningEnabled:    boolean;
  lastScanTime:       string | null;
  definitionsVersion: string;
  definitionsAgeHours: number;
  filesMonitoredToday: number;
  threatsToday:       number;
  threatsTotal:       number;
  agentVersion:       string;
}

export const statusStore = writable<AgentStatus | null>(null);
export const loadingStore = writable(false);

async function invokeOrMock<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  // In Tauri context, use real IPC
  if (typeof window !== 'undefined' && (window as any).__TAURI_INTERNALS__) {
    const { invoke } = await import('@tauri-apps/api/core');
    return invoke<T>(command, args);
  }
  // Browser/dev fallback — return mock data
  return getMockData(command) as T;
}

export async function loadStatus() {
  loadingStore.set(true);
  try {
    const status = await invokeOrMock<AgentStatus>('get_status');
    statusStore.set(status);
  } catch (e) {
    console.error('Failed to load status:', e);
  } finally {
    loadingStore.set(false);
  }
}

// ── Mock data for browser dev mode ──────────────────────────────────────────
function getMockData(command: string): unknown {
  const now = new Date().toISOString();
  const minus = (h: number) => new Date(Date.now() - h * 3600_000).toISOString();

  switch (command) {
    case 'get_status':
      return {
        protectionStatus:    'PROTECTED',
        realtimeMonitoring:  true,
        scanningEnabled:     true,
        lastScanTime:        minus(2),
        definitionsVersion:  '26481',
        definitionsAgeHours: 4,
        filesMonitoredToday: 1247,
        threatsToday:        0,
        threatsTotal:        3,
        agentVersion:        '0.1.0',
      } satisfies AgentStatus;

    case 'get_scan_history':
      return [
        { id:'s1', scanType:'QUICK_SCAN', startedAt: minus(2),   completedAt: minus(1.9), filesScanned:847,    threatsFound:0, durationSecs:183,  status:'COMPLETE' },
        { id:'s2', scanType:'FULL_SCAN',  startedAt: minus(26),  completedAt: minus(25.6),filesScanned:48391,  threatsFound:2, durationSecs:1340, status:'COMPLETE' },
        { id:'s3', scanType:'QUICK_SCAN', startedAt: minus(50),  completedAt: minus(49.9),filesScanned:912,    threatsFound:1, durationSecs:241,  status:'COMPLETE' },
        { id:'s4', scanType:'FULL_SCAN',  startedAt: minus(170), completedAt: minus(169.7),filesScanned:47102, threatsFound:0, durationSecs:1148, status:'COMPLETE' },
      ];

    case 'get_threats':
      return [
        { id:'t1', detectedAt:minus(27),  path:'C:\\Users\\Carlos\\Downloads\\crack_photoshop.exe', verdict:'INFECTED',   threatName:'Win.Trojan.Generic-9953295-0',  severity:'CRITICAL', actionTaken:'QUARANTINED', scanType:'FULL_SCAN'  },
        { id:'t2', detectedAt:minus(27),  path:'C:\\Users\\Carlos\\Downloads\\keygen.dll',          verdict:'SUSPICIOUS', threatName:'Heuristics.Broken.Executable',   severity:'MEDIUM',   actionTaken:'LOGGED',      scanType:'FULL_SCAN'  },
        { id:'t3', detectedAt:minus(55),  path:'C:\\Users\\Carlos\\Desktop\\invoice_doc.exe',       verdict:'INFECTED',   threatName:'Win.Malware.Emotet-9827123-1',   severity:'CRITICAL', actionTaken:'QUARANTINED', scanType:'ON_ACCESS'  },
      ];

    case 'get_definitions_info':
      return { version:'26481', updatedAt: minus(4), ageHours:4, virusCount:8723142, status:'UP_TO_DATE' };

    case 'run_quick_scan':
    case 'run_full_scan':
      return 'Scan started';

    default:
      return null;
  }
}
