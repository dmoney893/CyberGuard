
import { useState } from "react";
import {
  pairAgent,
  checkAgentHealth,
  getAgentPort,
  setAgentPort,
} from "../lib/localAgent";

type AgentPairingProps = {
  onPaired: () => void;
};

export default function AgentPairing({
  onPaired,
}: AgentPairingProps) {
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [port, setPort] = useState(getAgentPort);

  const handlePair = async () => {
    if (!code.trim()) return;

    setLoading(true);
    setError("");

    try {
      setAgentPort(port);
      await checkAgentHealth();
      await pairAgent(code);
      setCode("");
      onPaired();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to pair device."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="agent-pairing">
      <h2>Connect Your Device</h2>

      <p>
        Open the CyberGuard Agent on your computer
        and enter the pairing code displayed there.
      </p>

      <form
        onSubmit={(event) => {
          event.preventDefault();
          void handlePair();
        }}
      >
        <label>
          Agent port
          <input type="number" min="1024" max="65535" value={port}
            onChange={(event) => setPort(event.target.value)} required disabled={loading} />
        </label>
        <input
          type="text"
          placeholder="Enter pairing code"
          value={code}
          onChange={(event) => setCode(event.target.value)}
          autoComplete="off"
          required
        />

        <button type="submit" disabled={loading || !code.trim()}>
          {loading ? "Connecting..." : "Pair Device"}
        </button>
      </form>

      {error && <p role="alert">{error}</p>}
    </div>
  );
}
