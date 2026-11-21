/**
 * Local-scanner incident correlation API (127.0.0.1:8765).
 */

export const INCIDENTS_SCANNER_URL = "http://127.0.0.1:8765";

export type IncidentStatus = "open" | "resolved" | "dismissed";

export type IncidentStoryStep = {
  ts: number;
  node_id: string;
  kind: string;
  text: string;
};

export type IncidentRuleHit = {
  rule_id: string;
  name: string;
  severity: string;
  node_ids: string[];
  detail?: string;
};

export type IncidentSummary = {
  id: string;
  created_at: number;
  updated_at: number;
  severity: string;
  score: number;
  status: IncidentStatus | string;
  title: string;
  node_ids: string[];
  rule_hits: IncidentRuleHit[];
  storyline: IncidentStoryStep[];
};

export type IncidentNode = {
  id: string;
  kind: string;
  label: string;
  base_risk: number;
  propagated_risk: number;
  first_seen?: number;
  last_seen?: number;
  attrs?: Record<string, unknown>;
  max_parent?: {
    parent: string;
    edge_kind: string;
    edge_ts: number;
    contribution: number;
  } | null;
};

export type IncidentEdge = {
  src: string;
  dst: string;
  kind: string;
  ts: number;
  event_id?: string | null;
};

export type IncidentDetail = IncidentSummary & {
  nodes: IncidentNode[];
  edges: IncidentEdge[];
};

async function scannerFetch(
  path: string,
  init?: RequestInit,
): Promise<Response> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 4000);
  try {
    return await fetch(`${INCIDENTS_SCANNER_URL}${path}`, {
      ...init,
      signal: init?.signal ?? controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...(init?.headers ?? {}),
      },
    });
  } finally {
    window.clearTimeout(timeout);
  }
}

export async function checkScannerReachable(): Promise<boolean> {
  try {
    const response = await scannerFetch("/health");
    return response.ok;
  } catch {
    return false;
  }
}

export async function listIncidents(
  status: IncidentStatus | "all" = "open",
): Promise<IncidentSummary[]> {
  const response = await scannerFetch(
    `/incidents?status=${encodeURIComponent(status)}`,
  );
  if (!response.ok) {
    throw new Error("Unable to load incidents.");
  }
  const data = (await response.json()) as {
    incidents?: IncidentSummary[];
  };
  return Array.isArray(data.incidents) ? data.incidents : [];
}

export async function getIncident(id: string): Promise<IncidentDetail> {
  const response = await scannerFetch(`/incidents/${encodeURIComponent(id)}`);
  if (response.status === 404) {
    throw new Error("Incident not found.");
  }
  if (!response.ok) {
    throw new Error("Unable to load incident details.");
  }
  return (await response.json()) as IncidentDetail;
}

export async function setIncidentStatus(
  id: string,
  status: IncidentStatus,
): Promise<void> {
  const response = await scannerFetch(
    `/incidents/${encodeURIComponent(id)}/status`,
    {
      method: "POST",
      body: JSON.stringify({ status }),
    },
  );
  if (!response.ok) {
    throw new Error("Unable to update incident status.");
  }
}
