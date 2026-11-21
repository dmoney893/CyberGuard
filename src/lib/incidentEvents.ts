/**
 * Fire-and-forget correlation events for the local CyberGuard scanner.
 *
 * Never throws. If the scanner is offline, events are queued in localStorage
 * and retried later.
 */

import type { EmailResult, WebsiteHistoryEntry } from "../api/emailApi";

const SCANNER_URL = "http://127.0.0.1:8765";
const QUEUE_KEY = "cyberguard.incidentEvents.queue";
const MAX_QUEUE = 500;
const FLUSH_BATCH = 100;

export type IncidentEventSource =
  | "email"
  | "website"
  | "file_check"
  | "gmail_attachment";

export type IncidentEntity = {
  id: string;
  kind: string;
  label: string;
  base_risk?: number;
  attrs?: Record<string, unknown>;
};

export type IncidentEdge = {
  src: string;
  dst: string;
  kind: string;
};

export type IncidentEvent = {
  id: string;
  source: IncidentEventSource;
  type: string;
  ts: number;
  risk: number;
  payload?: Record<string, unknown>;
  entities?: IncidentEntity[];
  edges?: IncidentEdge[];
};

let flushTimer: number | null = null;
let flushing = false;

function clampRisk(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function normalizeDomain(host: string): string {
  const lower = host.trim().toLowerCase();
  return lower.startsWith("www.") ? lower.slice(4) : lower.replace(/\.$/, "");
}

function normalizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const host = normalizeDomain(parsed.hostname);
    const path = parsed.pathname || "/";
    return `${parsed.protocol}//${host}${path}${parsed.search}`;
  } catch {
    return url.trim().toLowerCase();
  }
}

function emailEntityId(result: {
  id?: string | null;
  sender: string;
  subject: string;
  ts: number;
}): string {
  if (result.id) return `email:${result.id}`;
  const material = `${result.sender}|${result.subject}|${result.ts}`;
  let hash = 0;
  for (let i = 0; i < material.length; i += 1) {
    hash = (hash * 31 + material.charCodeAt(i)) >>> 0;
  }
  return `email:${hash.toString(16)}`;
}

function readQueue(): IncidentEvent[] {
  try {
    const raw = localStorage.getItem(QUEUE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as IncidentEvent[]) : [];
  } catch {
    return [];
  }
}

function writeQueue(events: IncidentEvent[]) {
  try {
    localStorage.setItem(
      QUEUE_KEY,
      JSON.stringify(events.slice(-MAX_QUEUE)),
    );
  } catch {
    /* private mode / quota */
  }
}

function scheduleFlush(delayMs = 250) {
  if (typeof window === "undefined") return;
  if (flushTimer != null) window.clearTimeout(flushTimer);
  flushTimer = window.setTimeout(() => {
    flushTimer = null;
    void flushQueue();
  }, delayMs);
}

async function flushQueue(): Promise<void> {
  if (flushing) return;
  flushing = true;

  try {
    let queue = readQueue();
    while (queue.length > 0) {
      const batch = queue.slice(0, FLUSH_BATCH);
      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), 2500);

      let ok = false;
      try {
        const response = await fetch(`${SCANNER_URL}/events/ingest`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ events: batch }),
          signal: controller.signal,
        });
        ok = response.ok;
      } catch {
        ok = false;
      } finally {
        window.clearTimeout(timeout);
      }

      if (!ok) {
        // Keep the queue; try again later.
        scheduleFlush(15_000);
        return;
      }

      queue = readQueue().slice(batch.length);
      writeQueue(queue);
    }
  } finally {
    flushing = false;
  }
}

/** Enqueue events and attempt an immediate flush. Never throws. */
export function pushEvents(events: IncidentEvent[]): void {
  try {
    if (!events.length) return;

    const normalized = events
      .filter((event) => event?.id && event.source && event.type)
      .map((event) => ({
        ...event,
        risk: clampRisk(event.risk),
        ts: Number.isFinite(event.ts) ? event.ts : Date.now() / 1000,
        payload: event.payload ?? {},
        entities: event.entities ?? [],
        edges: event.edges ?? [],
      }));

    if (!normalized.length) return;

    const queue = readQueue();
    const seen = new Set(queue.map((item) => item.id));
    for (const event of normalized) {
      if (seen.has(event.id)) continue;
      queue.push(event);
      seen.add(event.id);
    }
    writeQueue(queue);
    scheduleFlush(100);
  } catch {
    /* never throw into callers */
  }
}

export function websiteRiskFromLevel(
  level: WebsiteHistoryEntry["risk_level"] | string,
): number {
  switch (level) {
    case "HIGH_RISK":
      return 0.9;
    case "SUSPICIOUS":
      return 0.6;
    case "NO_KNOWN_THREAT":
      return 0.05;
    case "UNABLE_TO_VERIFY":
      return 0.2;
    default:
      return 0.2;
  }
}

export function fileRiskFromClassification(
  classification: string,
  riskScore?: number,
): number {
  if (typeof riskScore === "number" && Number.isFinite(riskScore)) {
    return clampRisk(riskScore / 100);
  }
  switch (classification) {
    case "HIGH RISK":
      return 0.9;
    case "SUSPICIOUS":
      return 0.6;
    case "SAFE":
      return 0.05;
    default:
      return 0.2;
  }
}

/** Build + push events for completed email analyses. */
export function pushEmailScanEvents(results: EmailResult[]): void {
  try {
    const now = Date.now() / 1000;
    const events: IncidentEvent[] = [];

    for (const result of results) {
      if (!result || result.classification === "ERROR") continue;

      const ts = now;
      const emailId = emailEntityId({
        id: result.id,
        sender: result.sender,
        subject: result.subject,
        ts,
      });
      const risk = clampRisk((result.risk_score ?? 0) / 100);
      const domains = [
        ...new Set(
          (result.link_domains ?? [])
            .map(normalizeDomain)
            .filter(Boolean),
        ),
      ];
      const urls = [
        ...new Set(
          (result.link_urls ?? result.links?.map((link) => link.url) ?? [])
            .map((url) => url.trim())
            .filter(Boolean),
        ),
      ];

      const entities: IncidentEntity[] = [
        {
          id: emailId,
          kind: "email",
          label: result.subject?.trim() || result.sender || "Email",
          base_risk: risk,
          attrs: {
            sender: result.sender,
            subject: result.subject,
            classification: result.classification,
            source: result.source,
            message_id: result.id,
          },
        },
      ];

      const edges: IncidentEdge[] = [];

      for (const domain of domains) {
        const domainId = `domain:${domain}`;
        entities.push({
          id: domainId,
          kind: "domain",
          label: domain,
          base_risk: 0,
          attrs: { host: domain },
        });
        edges.push({ src: emailId, dst: domainId, kind: "links_to" });
      }

      for (const url of urls) {
        const normalized = normalizeUrl(url);
        if (!normalized) continue;
        const urlId = `url:${normalized}`;
        entities.push({
          id: urlId,
          kind: "url",
          label: normalized,
          base_risk: 0,
          attrs: { url: normalized },
        });
        edges.push({ src: emailId, dst: urlId, kind: "links_to" });
      }

      events.push({
        id: `email:scan:${emailId}`,
        source: "email",
        type: "email_scanned",
        ts,
        risk,
        payload: {
          sender: result.sender,
          subject: result.subject,
          classification: result.classification,
          risk_score: result.risk_score,
          link_domains: domains,
          link_urls: urls,
        },
        entities,
        edges,
      });
    }

    pushEvents(events);
  } catch {
    /* never throw */
  }
}

/** Build + push visited events for website history rows. */
export function pushWebsiteVisitEvents(
  entries: WebsiteHistoryEntry[],
): void {
  try {
    const events: IncidentEvent[] = [];

    for (const entry of entries) {
      if (!entry?.id || !entry.url || !entry.domain) continue;

      const visitedAt = Date.parse(entry.visited_at);
      const ts = Number.isFinite(visitedAt) ? visitedAt / 1000 : Date.now() / 1000;
      const risk = websiteRiskFromLevel(entry.risk_level);
      const domain = normalizeDomain(entry.domain);
      const normalizedUrl = normalizeUrl(entry.url);
      const domainId = `domain:${domain}`;
      const urlId = `url:${normalizedUrl}`;

      events.push({
        id: `website:visited:${entry.id}`,
        source: "website",
        type: "visited",
        ts,
        risk,
        payload: {
          url: entry.url,
          domain,
          risk_level: entry.risk_level,
          risk_score: entry.risk_score,
          visited_at: entry.visited_at,
          history_id: entry.id,
        },
        entities: [
          {
            id: domainId,
            kind: "domain",
            label: domain,
            base_risk: risk,
            attrs: {
              host: domain,
              risk_level: entry.risk_level,
              visited_at: entry.visited_at,
            },
          },
          {
            id: urlId,
            kind: "url",
            label: normalizedUrl,
            base_risk: risk,
            attrs: {
              url: normalizedUrl,
              risk_level: entry.risk_level,
              visited_at: entry.visited_at,
            },
          },
        ],
        edges: [
          { src: domainId, dst: urlId, kind: "visited" },
        ],
      });
    }

    pushEvents(events);
  } catch {
    /* never throw */
  }
}

export function pushFileCheckEvent(input: {
  sha256: string;
  filename: string;
  classification: string;
  riskScore?: number;
  source?: "file_check" | "gmail_attachment";
  gmailMessageId?: string | null;
}): void {
  try {
    const sha256 = (input.sha256 || "").trim().toLowerCase();
    if (!sha256) return;

    const risk = fileRiskFromClassification(
      input.classification,
      input.riskScore,
    );
    const fileId = `file:${sha256}`;
    const source = input.source ?? "file_check";
    const ts = Date.now() / 1000;
    const entities: IncidentEntity[] = [
      {
        id: fileId,
        kind: "file",
        label: input.filename || sha256.slice(0, 12),
        base_risk: risk,
        attrs: {
          sha256,
          filename: input.filename,
          classification: input.classification,
        },
      },
    ];
    const edges: IncidentEdge[] = [];

    if (source === "gmail_attachment" && input.gmailMessageId) {
      const emailId = `email:${input.gmailMessageId}`;
      entities.push({
        id: emailId,
        kind: "email",
        label: `Gmail ${input.gmailMessageId}`,
        base_risk: 0,
        attrs: { message_id: input.gmailMessageId },
      });
      edges.push({ src: emailId, dst: fileId, kind: "attached" });
    }

    pushEvents([
      {
        id: `${source}:${sha256}:${input.gmailMessageId ?? "local"}`,
        source,
        type:
          source === "gmail_attachment"
            ? "gmail_attachment_scanned"
            : "file_checked",
        ts,
        risk,
        payload: {
          sha256,
          filename: input.filename,
          classification: input.classification,
          risk_score: input.riskScore,
          gmail_message_id: input.gmailMessageId ?? null,
        },
        entities,
        edges,
      },
    ]);
  } catch {
    /* never throw */
  }
}

// Retry queued events when the tab becomes active again.
if (typeof window !== "undefined") {
  window.addEventListener("focus", () => scheduleFlush(500));
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") scheduleFlush(500);
  });
  scheduleFlush(1500);
}
