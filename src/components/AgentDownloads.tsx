export default function AgentDownloads() {
  return (
    <div className="agent-downloads">
      <a className="agent-install-download" href="/downloads/CyberGuardSetup.exe" download>
        Download for Windows
      </a>
      <a className="agent-install-download" href="/downloads/CyberGuard-Agent-mac-arm64.zip" download>
        Download for Mac — Apple Silicon (test build)
      </a>
      <p>
        Mac: extract the ZIP, move CyberGuard Agent to Applications, and open it.
        This test build is not Apple notarized and may be blocked by macOS.
        Intel Macs are not supported by this download.
      </p>
      <details>
        <summary>Mac says “CyberGuard Agent Not Opened”?</summary>
        <ol>
          <li>Click <strong>Done</strong> in the warning, rather than Move to Trash.</li>
          <li>Open <strong>Apple menu → System Settings → Privacy &amp; Security</strong>.</li>
          <li>Scroll to the CyberGuard Agent blocked notice and click <strong>Open Anyway</strong>.</li>
          <li>Authenticate if requested, then confirm <strong>Open</strong>. Keep the agent window open and use its <strong>Open CyberGuard Website</strong> button to pair.</li>
        </ol>
        <p>
          Only approve the CyberGuard test download supplied by your team. Do not disable Gatekeeper.
          Approval is normally needed once per copy. If Open Anyway is missing, try opening the app again and return to Settings.
          A school-managed Mac may need IT approval.
        </p>
        <a href="https://support.apple.com/en-us/102445" target="_blank" rel="noreferrer">Apple’s instructions for opening downloaded apps</a>
      </details>
      <p>
        Keep the agent open while using device features. Malware scans require
        a separate ClamAV installation and signature database.
      </p>
    </div>
  );
}
