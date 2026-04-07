/**
 * API layer — wraps Tauri invoke() calls with fallback to mock data
 * when running in a plain browser (dev without Tauri).
 */
import type {
  AgentStatus, ScanHistoryEntry, ThreatEntry, DefinitionsInfo
} from './types';

async function invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (typeof window !== 'undefined' && (window as any).__TAURI_INTERNALS__) {
    const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
    return tauriInvoke<T>(command, args);
  }
  // Browser dev fallback
  return mockData(command, args) as T;
}

export const api = {
  getStatus:          ()                          => invoke<AgentStatus>('get_status'),
  getScanHistory:     (limit = 20)                => invoke<ScanHistoryEntry[]>('get_scan_history', { limit }),
  getThreats:         (sinceHours = 168)          => invoke<ThreatEntry[]>('get_threats', { sinceHours }),
  getDefinitionsInfo: ()                          => invoke<DefinitionsInfo>('get_definitions_info'),
  runQuickScan:       ()                          => invoke<string>('run_quick_scan'),
  runFullScan:        ()                          => invoke<string>('run_full_scan'),
  dismissThreat:      (threatId: string)          => invoke<void>('dismiss_threat', { threatId }),
};

// ── Browser mock data ─────────────────────────────────────────────────────────
function ago(h: number) { return new Date(Date.now() - h * 3600_000).toISOString(); }

function mockData(cmd: string, _args?: any): unknown {
  switch (cmd) {
    case 'get_status': return {
      protectionStatus:    'PROTECTED',
      realtimeMonitoring:  true,
      scanningEnabled:     true,
      lastScanTime:        ago(2),
      definitionsVersion:  '26481',
      definitionsAgeHours: 4,
      filesMonitoredToday: 1247,
      threatsToday:        0,
      threatsTotal:        3,
      agentVersion:        '0.1.0',
    } satisfies AgentStatus;

    case 'get_scan_history': return [
      { id:'s1', scanType:'QUICK_SCAN', startedAt:ago(2),   completedAt:ago(1.95), filesScanned:847,   threatsFound:0, durationSecs:183,  status:'COMPLETE' },
      { id:'s2', scanType:'FULL_SCAN',  startedAt:ago(26),  completedAt:ago(25.6), filesScanned:48391, threatsFound:2, durationSecs:1340, status:'COMPLETE' },
      { id:'s3', scanType:'QUICK_SCAN', startedAt:ago(50),  completedAt:ago(49.9), filesScanned:912,   threatsFound:1, durationSecs:241,  status:'COMPLETE' },
      { id:'s4', scanType:'FULL_SCAN',  startedAt:ago(170), completedAt:ago(169.7),filesScanned:47102, threatsFound:0, durationSecs:1148, status:'COMPLETE' },
    ];

    case 'get_threats': return [
      { id:'t1', detectedAt:ago(27), path:'C:\\Users\\Carlos\\Downloads\\crack_photoshop.exe', verdict:'INFECTED',   threatName:'Win.Trojan.Generic-9953295-0', severity:'CRITICAL', actionTaken:'QUARANTINED', scanType:'FULL_SCAN', extension:'exe', sizeBytes:4234120 },
      { id:'t2', detectedAt:ago(27), path:'C:\\Users\\Carlos\\Downloads\\keygen.dll',          verdict:'SUSPICIOUS', threatName:'Heuristics.Broken.Executable',  severity:'MEDIUM',   actionTaken:'LOGGED',      scanType:'FULL_SCAN', extension:'dll', sizeBytes:128000  },
      { id:'t3', detectedAt:ago(55), path:'C:\\Users\\Carlos\\Desktop\\invoice_doc.exe',       verdict:'INFECTED',   threatName:'Win.Malware.Emotet-9827123-1',  severity:'CRITICAL', actionTaken:'QUARANTINED', scanType:'ON_ACCESS', extension:'exe', sizeBytes:2048576 },
    ];

    case 'get_definitions_info': return {
      version:'26481', updatedAt:ago(4), ageHours:4, virusCount:8723142, status:'UP_TO_DATE'
    };

    default: return null;
  }
}
