// Shared TypeScript types — mirror Rust structs in commands.rs exactly

export interface AgentStatus {
  protectionStatus:    'PROTECTED' | 'AT_RISK' | 'SCANNING' | 'DISABLED';
  realtimeMonitoring:  boolean;
  scanningEnabled:     boolean;
  lastScanTime:        string | null;
  definitionsVersion:  string;
  definitionsAgeHours: number;
  filesMonitoredToday: number;
  threatsToday:        number;
  threatsTotal:        number;
  agentVersion:        string;
}

export interface ScanHistoryEntry {
  id:           string;
  scanType:     'QUICK_SCAN' | 'FULL_SCAN' | 'ON_ACCESS';
  startedAt:    string;
  completedAt:  string;
  filesScanned: number;
  threatsFound: number;
  durationSecs: number;
  status:       'COMPLETE' | 'CANCELLED' | 'RUNNING';
}

export interface ThreatEntry {
  id:          string;
  detectedAt:  string;
  path:        string;
  verdict:     'INFECTED' | 'SUSPICIOUS';
  threatName:  string;
  severity:    'CRITICAL' | 'MEDIUM';
  actionTaken: 'QUARANTINED' | 'LOGGED';
  scanType:    string;
  extension:   string;
  sizeBytes:   number | null;
}

export interface DefinitionsInfo {
  version:    string;
  updatedAt:  string;
  ageHours:   number;
  virusCount: number;
  status:     'UP_TO_DATE' | 'OUTDATED' | 'UPDATING';
}

export interface ScanProgress {
  jobId:       string;
  totalFiles:  number;
  scannedFiles:number;
  threatsFound:number;
  currentFile: string | null;
  percent:     number;
}
