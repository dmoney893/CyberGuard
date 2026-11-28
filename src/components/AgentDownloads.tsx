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
      <p>
        Keep the agent open while using device features. Malware scans require
        a separate ClamAV installation and signature database.
      </p>
    </div>
  );
}
