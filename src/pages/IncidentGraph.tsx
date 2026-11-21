import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import {
  Background,
  Controls,
  MarkerType,
  ReactFlow,
  Handle,
  Position,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  AlertTriangle,
  CheckCircle2,
  FileWarning,
  GitBranch,
  Loader2,
  Mail,
  Network,
  Server,
  Sparkles,
  XCircle,
} from "lucide-react";

import { useAuth } from "../context/AuthContext";
import { assistantProvider } from "../lib/assistant";
import {
  checkScannerReachable,
  getIncident,
  listIncidents,
  setIncidentStatus,
  type IncidentDetail,
  type IncidentNode,
  type IncidentStatus,
  type IncidentSummary,
} from "../lib/incidentsApi";

import "./IncidentGraph.css";

type StatusFilter = IncidentStatus | "all";

const KIND_COLORS: Record<string, string> = {
  email: "#7c3aed",
  domain: "#2563eb",
  url: "#0891b2",
  file: "#ea580c",
  process: "#dc2626",
  ip: "#059669",
};

function riskColor(risk: number, kind: string): string {
  const base = KIND_COLORS[kind] ?? "#64748b";
  if (risk >= 0.8) return base;
  if (risk >= 0.6) return base;
  return base;
}

function riskIntensity(risk: number): number {
  return Math.max(0.18, Math.min(1, 0.25 + risk * 0.75));
}

function formatTime(ts: number): string {
  if (!ts) return "—";
  const date = new Date(ts * 1000);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function KindIcon({ kind }: { kind: string }) {
  const size = 16;
  switch (kind) {
    case "email":
      return <Mail size={size} />;
    case "domain":
    case "url":
      return <Network size={size} />;
    case "file":
      return <FileWarning size={size} />;
    case "process":
      return <Server size={size} />;
    case "ip":
      return <GitBranch size={size} />;
    default:
      return <AlertTriangle size={size} />;
  }
}

type IncidentFlowNodeData = {
  label: string;
  kind: string;
  risk: number;
  selected: boolean;
};

function IncidentFlowNode({ data }: NodeProps) {
  const nodeData = data as IncidentFlowNodeData;
  const color = riskColor(nodeData.risk, nodeData.kind);
  const alpha = riskIntensity(nodeData.risk);

  return (
    <div
      className={`ig-node-chip${nodeData.selected ? " selected" : ""}`}
      style={{
        borderColor: color,
        background: `color-mix(in srgb, ${color} ${Math.round(alpha * 35)}%, white)`,
      }}
    >
      <Handle type="target" position={Position.Left} />
      <div className="ig-node-chip-top" style={{ color }}>
        <KindIcon kind={nodeData.kind} />
        <span className="ig-node-kind">{nodeData.kind}</span>
      </div>
      <div className="ig-node-label">{nodeData.label}</div>
      <div className="ig-node-risk">
        Risk {(nodeData.risk * 100).toFixed(0)}%
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const nodeTypes = { incident: IncidentFlowNode };

function buildFlow(
  detail: IncidentDetail,
  selectedId: string | null,
): { nodes: Node[]; edges: Edge[] } {
  const byId = new Map(detail.nodes.map((node) => [node.id, node]));

  // Prefer the storyline order for a clean left→right chain.
  // When a storyline exists, do NOT dump every leftover entity into the graph
  // (repeated demo seeds create duplicate process nodes and empty zoomed-out canvas).
  const storyOrder = (detail.storyline || [])
    .map((step) => step.node_id)
    .filter((id, index, all) => byId.has(id) && all.indexOf(id) === index);

  const orderedIds =
    storyOrder.length > 0
      ? storyOrder
      : [...detail.nodes]
          .sort((a, b) => (a.first_seen ?? 0) - (b.first_seen ?? 0))
          .map((node) => node.id);

  const nodes: Node[] = orderedIds.map((id, index) => {
    const node = byId.get(id)!;
    return {
      id: node.id,
      type: "incident",
      position: { x: index * 200, y: 24 },
      data: {
        label: node.label,
        kind: node.kind,
        risk: node.propagated_risk ?? node.base_risk ?? 0,
        selected: selectedId === node.id,
      },
    };
  });

  const idSet = new Set(orderedIds);
  const edges: Edge[] = detail.edges
    .filter((edge) => idSet.has(edge.src) && idSet.has(edge.dst))
    .map((edge, index) => ({
      id: `${edge.src}-${edge.kind}-${edge.dst}-${index}`,
      source: edge.src,
      target: edge.dst,
      label: edge.kind.replace(/_/g, " "),
      markerEnd: { type: MarkerType.ArrowClosed },
      style: { stroke: "#94a3b8" },
      labelStyle: { fill: "#64748b", fontSize: 11, fontWeight: 600 },
    }));

  return { nodes, edges };
}

function pickDefaultIncident(rows: IncidentSummary[]): string | null {
  if (!rows.length) return null;
  const ranked = [...rows].sort((a, b) => {
    const scoreDiff = (b.score ?? 0) - (a.score ?? 0);
    if (scoreDiff !== 0) return scoreDiff;
    return (b.storyline?.length ?? 0) - (a.storyline?.length ?? 0);
  });
  return ranked[0]?.id ?? null;
}

function IncidentGraph() {
  const { session, loading: authLoading } = useAuth();
  const [scannerUp, setScannerUp] = useState<boolean | null>(null);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("open");
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [explainText, setExplainText] = useState("");
  const [explaining, setExplaining] = useState(false);

  const refreshList = useCallback(async () => {
    const reachable = await checkScannerReachable();
    setScannerUp(reachable);
    if (!reachable) {
      setIncidents([]);
      setDetail(null);
      return;
    }

    try {
      const rows = await listIncidents(statusFilter);
      setIncidents(rows);
      setError("");
      setSelectedId((current) => {
        if (current && rows.some((row) => row.id === current)) return current;
        return pickDefaultIncident(rows);
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load incidents.");
    }
  }, [statusFilter]);

  useEffect(() => {
    if (!session) return;
    let active = true;

    const tick = async () => {
      if (!active) return;
      await refreshList();
    };

    void tick();
    const interval = window.setInterval(tick, 8000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [session, refreshList]);

  useEffect(() => {
    if (!selectedId || !scannerUp) {
      setDetail(null);
      return;
    }

    let active = true;
    setBusy(true);
    setExplainText("");
    setSelectedNodeId(null);

    void getIncident(selectedId)
      .then((data) => {
        if (!active) return;
        setDetail(data);
        setError("");
      })
      .catch((err) => {
        if (!active) return;
        setDetail(null);
        setError(err instanceof Error ? err.message : "Unable to load incident.");
      })
      .finally(() => {
        if (active) setBusy(false);
      });

    return () => {
      active = false;
    };
  }, [selectedId, scannerUp]);

  const selectedNode = useMemo(
    () => detail?.nodes.find((node) => node.id === selectedNodeId) ?? null,
    [detail, selectedNodeId],
  );

  const flow = useMemo(() => {
    if (!detail) return { nodes: [] as Node[], edges: [] as Edge[] };
    return buildFlow(detail, selectedNodeId);
  }, [detail, selectedNodeId]);

  const updateStatus = async (status: IncidentStatus) => {
    if (!selectedId) return;
    setBusy(true);
    try {
      await setIncidentStatus(selectedId, status);
      await refreshList();
      if (status !== "open") {
        setSelectedId(null);
        setDetail(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to update status.");
    } finally {
      setBusy(false);
    }
  };

  const explainIncident = async () => {
    if (!detail) return;
    setExplaining(true);
    setExplainText("");
    try {
      const nodeSummary = detail.nodes
        .map(
          (node) =>
            `- ${node.kind} “${node.label}”: base risk ${Math.round((node.base_risk ?? 0) * 100)}%, correlated risk ${Math.round((node.propagated_risk ?? 0) * 100)}%`,
        )
        .join("\n");
      const story = detail.storyline
        .map((step, index) => `${index + 1}. ${step.text}`)
        .join("\n");
      const rules = (detail.rule_hits || [])
        .map((hit) => `${hit.rule_id} ${hit.name}`)
        .join(", ");

      const prompt = `You are CyberGuard's security assistant. Explain this security incident for a non-technical user.

Cover:
1) What happened (short story)
2) How serious it is
3) Exactly 3 concrete next steps

Do not invent technical details that are not listed. Keep the tone calm and clear.

Incident title: ${detail.title}
Severity: ${detail.severity} (score ${detail.score})
Rules matched: ${rules || "none"}

Storyline:
${story || "No storyline available."}

Related items:
${nodeSummary || "None"}`;

      const reply = await assistantProvider.getReply([
        {
          id: "incident-explain",
          role: "user",
          content: prompt,
        },
      ]);
      setExplainText(reply);
    } catch (err) {
      setExplainText(
        err instanceof Error
          ? err.message
          : "Unable to explain this incident right now.",
      );
    } finally {
      setExplaining(false);
    }
  };

  if (authLoading) {
    return (
      <div className="incident-graph-page">
        <p>Loading...</p>
      </div>
    );
  }

  if (!session) {
    return <Navigate to="/dashboard" replace />;
  }

  if (scannerUp === false) {
    return (
      <div className="incident-graph-page">
        <div className="ig-topbar">
          <div className="ig-title-group">
            <div className="ig-title-icon">
              <GitBranch size={24} />
            </div>
            <div>
              <h1>Incidents</h1>
              <p>Cross-source attack chains from your local scanner</p>
            </div>
          </div>
          <span className="ig-connection disconnected">Scanner offline</span>
        </div>

        <div className="ig-offline">
          <h2>Start the local scanner</h2>
          <p>
            Incidents are correlated on your device. Start the CyberGuard local
            scanner the same way you do for System Guardian or Device Scanner,
            then return here.
          </p>
          <code>npm run scanner</code>
          <p style={{ marginTop: 18 }}>
            Or use <code>npm run dev:all</code> to run the app and scanner
            together.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="incident-graph-page">
      <div className="ig-topbar">
        <div className="ig-title-group">
          <div className="ig-title-icon">
            <GitBranch size={24} />
          </div>
          <div>
            <h1>Incidents</h1>
            <p>Cross-source attack chains from your local scanner</p>
          </div>
        </div>
        <span
          className={`ig-connection ${scannerUp ? "connected" : "disconnected"}`}
        >
          {scannerUp ? "Scanner connected" : "Checking…"}
        </span>
      </div>

      {error && <div className="ig-error">{error}</div>}

      <div className="ig-layout">
        <aside className="ig-list-panel">
          <div className="ig-list-header">
            <h2>Incidents</h2>
            <div className="ig-filters">
              {(["open", "resolved", "dismissed", "all"] as StatusFilter[]).map(
                (value) => (
                  <button
                    key={value}
                    type="button"
                    className={`ig-filter${statusFilter === value ? " active" : ""}`}
                    onClick={() => setStatusFilter(value)}
                  >
                    {value}
                  </button>
                ),
              )}
            </div>
          </div>

          <div className="ig-list">
            {incidents.length === 0 ? (
              <div className="ig-empty-list">
                No {statusFilter === "all" ? "" : `${statusFilter} `}
                incidents yet. Scan email, browse, or run{" "}
                <code>POST /events/demo</code> with the scanner demo flag.
              </div>
            ) : (
              incidents.map((incident) => (
                <button
                  key={incident.id}
                  type="button"
                  className={`ig-list-item${selectedId === incident.id ? " active" : ""}`}
                  onClick={() => setSelectedId(incident.id)}
                >
                  <div className="ig-list-item-top">
                    <span className={`ig-badge ${incident.severity}`}>
                      {incident.severity}
                    </span>
                    <span style={{ fontSize: 11, color: "#94a3b8" }}>
                      {incident.status}
                    </span>
                  </div>
                  <h3>{incident.title}</h3>
                  <div className="ig-list-meta">
                    <span>{formatTime(incident.updated_at || incident.created_at)}</span>
                    <span>{incident.storyline?.length ?? 0} steps</span>
                    <span>{Math.round((incident.score ?? 0) * 100)}%</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </aside>

        <section className="ig-main-panel">
          {!detail ? (
            <div className="ig-placeholder">
              {busy ? (
                <>
                  <Loader2 size={18} className="spin" /> Loading incident…
                </>
              ) : (
                "Select an incident to inspect the graph and storyline."
              )}
            </div>
          ) : (
            <>
              <div className="ig-main-header">
                <div>
                  <h2>{detail.title}</h2>
                  <p className="ig-main-sub">
                    <span className={`ig-badge ${detail.severity}`}>
                      {detail.severity}
                    </span>{" "}
                    · score {Math.round(detail.score * 100)}% · updated{" "}
                    {formatTime(detail.updated_at)}
                  </p>
                </div>
                <div className="ig-actions">
                  <button
                    type="button"
                    className="ig-btn primary"
                    onClick={() => void explainIncident()}
                    disabled={explaining}
                  >
                    <Sparkles size={15} />
                    {explaining ? "Explaining…" : "Explain this incident"}
                  </button>
                  {detail.status === "open" && (
                    <>
                      <button
                        type="button"
                        className="ig-btn"
                        onClick={() => void updateStatus("resolved")}
                        disabled={busy}
                      >
                        <CheckCircle2 size={15} />
                        Resolve
                      </button>
                      <button
                        type="button"
                        className="ig-btn danger"
                        onClick={() => void updateStatus("dismissed")}
                        disabled={busy}
                      >
                        <XCircle size={15} />
                        Dismiss
                      </button>
                    </>
                  )}
                </div>
              </div>

              <div className="ig-body">
                <div className="ig-graph-wrap">
                  <ReactFlow
                    key={detail.id}
                    nodes={flow.nodes}
                    edges={flow.edges}
                    nodeTypes={nodeTypes}
                    fitView
                    fitViewOptions={{ padding: 0.35, minZoom: 0.55, maxZoom: 1.05 }}
                    minZoom={0.5}
                    maxZoom={1.4}
                    nodesDraggable={false}
                    nodesConnectable={false}
                    elementsSelectable
                    onInit={(instance) => {
                      window.requestAnimationFrame(() => {
                        instance.fitView({
                          padding: 0.35,
                          minZoom: 0.55,
                          maxZoom: 1.05,
                        });
                      });
                    }}
                    onNodeClick={(_, node) => setSelectedNodeId(node.id)}
                    proOptions={{ hideAttribution: true }}
                  >
                    <Background gap={18} size={1} color="#dbe3ee" />
                    <Controls showInteractive={false} />
                  </ReactFlow>
                </div>

                <div className="ig-side">
                  <div className="ig-side-section">
                    <h3>Storyline</h3>
                    {detail.storyline?.length ? (
                      <ol className="ig-timeline">
                        {detail.storyline.map((step) => (
                          <li key={`${step.node_id}-${step.ts}-${step.text}`}>
                            <span className="ig-timeline-dot" />
                            <div>
                              <p className="ig-timeline-text">{step.text}</p>
                              <p className="ig-timeline-meta">
                                {step.kind} · {formatTime(step.ts)}
                              </p>
                            </div>
                          </li>
                        ))}
                      </ol>
                    ) : (
                      <p className="ig-main-sub">No storyline steps yet.</p>
                    )}
                  </div>

                  <div className="ig-side-section">
                    <h3>Selected node</h3>
                    {!selectedNode ? (
                      <p className="ig-main-sub">
                        Click a node in the graph to see why it is risky.
                      </p>
                    ) : (
                      <dl className="ig-node-details">
                        <dt>Kind</dt>
                        <dd>{selectedNode.kind}</dd>
                        <dt>Label</dt>
                        <dd>{selectedNode.label}</dd>
                        <dt>Base risk</dt>
                        <dd>{Math.round((selectedNode.base_risk ?? 0) * 100)}%</dd>
                        <dt>Propagated risk</dt>
                        <dd>
                          {Math.round((selectedNode.propagated_risk ?? 0) * 100)}%
                        </dd>
                        <dt>First seen</dt>
                        <dd>{formatTime(selectedNode.first_seen ?? 0)}</dd>
                        {selectedNode.max_parent && (
                          <>
                            <dt>Why risky</dt>
                            <dd>
                              Inherited from {selectedNode.max_parent.parent} via{" "}
                              {selectedNode.max_parent.edge_kind.replace(/_/g, " ")}
                            </dd>
                          </>
                        )}
                        {selectedNode.kind === "process" && (
                          <>
                            <dt>Action</dt>
                            <dd>
                              <Link to="/system-guardian">
                                Open System Guardian to review or end this process
                              </Link>
                            </dd>
                          </>
                        )}
                        {selectedNode.attrs && (
                          <>
                            <dt>Details</dt>
                            <dd>
                              <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>
                                {JSON.stringify(selectedNode.attrs, null, 2)}
                              </pre>
                            </dd>
                          </>
                        )}
                      </dl>
                    )}
                  </div>

                  {(explainText || explaining) && (
                    <div className="ig-side-section">
                      <h3>Explanation</h3>
                      <div className="ig-explain">
                        {explaining ? "Writing a plain-English summary…" : explainText}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </section>
      </div>
    </div>
  );
}

export default IncidentGraph;
