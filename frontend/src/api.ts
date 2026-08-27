import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8787/api';

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

// ─── Types ───────────────────────────────────────────────────────────────────

export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingStatus = 'NEW' | 'ACKNOWLEDGED' | 'IN_PROGRESS' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface Target {
  id: string;
  name: string;
  value: string;
  target_type: string;
  description?: string;
  authorization_confirmed: boolean;
  is_active: boolean;
  created_at: string;
}

export interface Scan {
  id: string;
  target_id: string;
  status: ScanStatus;
  tools_used: string[];
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  created_at: string;
  completed_at?: string;
  error_message?: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  target_id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: string;
  status: FindingStatus;
  affected_component?: string;
  description?: string;
  evidence?: string;
  root_cause?: string;
  potential_impact?: string;
  remediation?: string;
  ai_explanation?: string;
  detected_by: string;
  detected_at: string;
}

export interface RemediationAction {
  id: string;
  finding_id: string;
  action_type: string;
  title: string;
  description?: string;
  steps?: string[];
  patch_diff?: string;
  target_file?: string;
  status: string;
  verification_result?: {
    passed: boolean;
    method: string;
    notes: string;
  };
  created_at: string;
}

export interface ActivityLog {
  id: string;
  event_type: string;
  message: string;
  level: string;
  details?: Record<string, any>;
  scan_id?: string;
  finding_id?: string;
  created_at: string;
}

export interface DashboardStats {
  targets: { total: number; active: number };
  scans: { total: number; running: number; completed: number; failed: number };
  findings: {
    total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
  };
  tools: Record<string, boolean>;
}

// ─── API functions ────────────────────────────────────────────────────────────

export const targetsApi = {
  list: () => api.get<Target[]>('/targets/').then(r => r.data),
  get: (id: string) => api.get<Target>(`/targets/${id}`).then(r => r.data),
  create: (data: Partial<Target>) => api.post<Target>('/targets/', data).then(r => r.data),
  delete: (id: string) => api.delete(`/targets/${id}`),
};

export const scansApi = {
  list: (params?: any) => api.get<Scan[]>('/scans/', { params }).then(r => r.data),
  get: (id: string) => api.get<Scan>(`/scans/${id}`).then(r => r.data),
  create: (data: { target_id: string; tools: string[]; authorization_confirmed: boolean }) =>
    api.post<Scan>('/scans/', data).then(r => r.data),
  cancel: (id: string) => api.post<Scan>(`/scans/${id}/cancel`).then(r => r.data),
};

export const findingsApi = {
  list: (params?: any) => api.get<Finding[]>('/findings/', { params }).then(r => r.data),
  get: (id: string) => api.get<Finding>(`/findings/${id}`).then(r => r.data),
  updateStatus: (id: string, status: FindingStatus) =>
    api.patch<Finding>(`/findings/${id}/status`, { status }).then(r => r.data),
};

export const remediationApi = {
  list: (findingId: string) =>
    api.get<RemediationAction[]>(`/remediation/finding/${findingId}`).then(r => r.data),
  generate: (findingId: string) =>
    api.post<RemediationAction>('/remediation/generate', { finding_id: findingId }).then(r => r.data),
  approve: (id: string) => api.post<RemediationAction>(`/remediation/${id}/approve`).then(r => r.data),
  reject: (id: string) => api.post<RemediationAction>(`/remediation/${id}/reject`).then(r => r.data),
  verify: (id: string) => api.post<RemediationAction>(`/remediation/${id}/verify`).then(r => r.data),
};

export const activityApi = {
  list: (params?: any) => api.get<ActivityLog[]>('/activity/', { params }).then(r => r.data),
};

export const statsApi = {
  dashboard: () => api.get<DashboardStats>('/health/dashboard').then(r => r.data),
};

export const toolsApi = {
  status: () => api.get<Record<string, any>>('/tools/status').then(r => r.data),
};

export const reportsApi = {
  generate: (scan_id: string, format: string) =>
    api.post('/reports/generate', { scan_id, format }, { responseType: 'blob' }),
};
