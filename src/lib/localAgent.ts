
const AGENT_URL = (import.meta.env.VITE_AGENT_URL ?? "http://127.0.0.1:8765").replace(/\/$/, "");

export function getAgentPort(): string {
  try {
    const requested = new URLSearchParams(window.location.search).get("agentPort");
    const saved = sessionStorage.getItem("cyberguard-agent-port");
    const port = requested ?? saved;
    if (port && /^\d+$/.test(port) && Number(port) >= 1024 && Number(port) <= 65535) {
      return port;
    }
  } catch { /* Browser storage may be unavailable. */ }
  return new URL(AGENT_URL).port || "8765";
}

export function setAgentPort(port: string): void {
  if (!/^\d+$/.test(port) || Number(port) < 1024 || Number(port) > 65535) {
    throw new Error("Enter a port between 1024 and 65535.");
  }
  const url = new URL(window.location.href);
  url.searchParams.set("agentPort", port);
  window.history.replaceState(null, "", url);
  try { sessionStorage.setItem("cyberguard-agent-port", port); } catch { /* Optional. */ }
  disconnectAgent();
}

function agentUrl(): string {
  // Only the port is user-selectable; never send pairing tokens to a remote host.
  return `http://127.0.0.1:${getAgentPort()}`;
}

async function localFetch(path: string, options: RequestInit = {}): Promise<Response> {
  try {
    const requestOptions: RequestInit & { targetAddressSpace: string } = {
      ...options,
      targetAddressSpace: "loopback",
      signal: options.signal ?? AbortSignal.timeout(path === "/health" ? 15000 : 130000),
    };
    return await fetch(`${agentUrl()}${path}`, requestOptions);
  } catch {
    throw new Error(`Cannot reach CyberGuard Agent on port ${getAgentPort()}. Keep the app open, match the port shown in its window, and allow this website to connect to apps on your device in browser settings.`);
  }
}

let sessionToken: string | null = null;

export type AgentHealth = {
  status: string;
  operating_system: string;
  supported: boolean;
};

export async function checkAgentHealth(): Promise<AgentHealth> {
  const response = await localFetch("/health");

  if (!response.ok) {
    throw new Error("CyberGuard Agent is unavailable.");
  }

  const data: AgentHealth = await response.json();
  if (data.status !== "ready" || typeof data.supported !== "boolean") {
    throw new Error("This port is not serving a compatible CyberGuard Agent.");
  }
  return data;
}

export async function pairAgent(code: string): Promise<void> {
  const response = await localFetch("/pair", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ code: code.trim() }),
  });

  if (!response.ok) {
    throw new Error("Invalid or expired pairing code.");
  }

  const data: { token: string } = await response.json();

  sessionToken = data.token;
}

export function isAgentPaired(): boolean {
  return sessionToken !== null;
}

export function disconnectAgent(): void {
  sessionToken = null;
}

export async function agentFetch(
  path: string,
  options: RequestInit = {}
): Promise<Response> {
  if (!sessionToken) {
    throw new Error("Pair your device with CyberGuard first.");
  }

  const headers = new Headers(options.headers);
  headers.set("Authorization", `Bearer ${sessionToken}`);

  const response = await localFetch(path, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    disconnectAgent();
    throw new Error(
      "Your device pairing expired. Please reconnect."
    );
  }

  return response;
}
