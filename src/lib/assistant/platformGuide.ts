/**
 * CyberGuard in-app features the assistant can explain and deep-link to.
 * Keep paths in sync with App.tsx routes.
 */
export type PlatformFeature = {
  id: string;
  name: string;
  path: string;
  summary: string;
  howTo: string;
  keywords: string[];
};

export const PLATFORM_FEATURES: PlatformFeature[] = [
  {
    id: "dashboard",
    name: "Dashboard",
    path: "/dashboard",
    summary:
      "Your CyberGuard home screen with an overview of tools and quick actions.",
    howTo:
      "Open Dashboard from the left sidebar (top item), or go to [Dashboard](/dashboard).",
    keywords: [
      "dashboard",
      "home",
      "home screen",
      "overview",
      "main page",
      "where do i start",
      "getting started",
    ],
  },
  {
    id: "website-tracker",
    name: "Website Tracker",
    path: "/website-tracker",
    summary:
      "Review websites you have visited with risk scores (Safe, Suspicious, High Risk).",
    howTo:
      "Open **Website Tracker** in the left sidebar, or go to [Website Tracker](/website-tracker). Search or sort the list by domain, risk score, or time visited.",
    keywords: [
      "website tracker",
      "track websites",
      "visited sites",
      "site history",
      "domain risk",
      "website risk",
      "check a website",
      "is this site",
      "url checker",
      "browsing history",
    ],
  },
  {
    id: "email-scanner",
    name: "Email Scanner",
    path: "/email-scanner",
    summary:
      "Scan emails for phishing risk. Paste emails manually or connect Gmail (read-only) and analyze selected messages.",
    howTo: `Open **Email Scanner** in the left sidebar, or go to [Email Scanner](/email-scanner).

**Two ways to scan**
1. Paste emails manually — add sender, subject, body, and links, then analyze.
2. Connect Gmail — sign in with Google (read-only), pick up to 50 messages, then analyze.

Results show a risk score, SAFE/PHISHING classification, and a plain-English explanation.`,
    keywords: [
      "email scanner",
      "scan email",
      "scan emails",
      "check email",
      "analyze email",
      "gmail",
      "connect gmail",
      "phishing scan",
      "paste email",
      "inbox scan",
      "email risk",
    ],
  },
  {
    id: "security-checker",
    name: "Security Checker",
    path: "/security-checker",
    summary:
      "Run security checks from CyberGuard (page is available in the sidebar; more checks are being added).",
    howTo:
      "Open Security Checker in the left sidebar, or go to [Security Checker](/security-checker).",
    keywords: [
      "security checker",
      "security check",
      "check security",
      "scan security",
      "vulnerability",
      "safety check",
    ],
  },
  {
    id: "team-security",
    name: "Team Security",
    path: "/organization",
    summary:
      "Create or join an organization, invite members, and manage team protection.",
    howTo: `Open Team Security in the left sidebar, or go to [Team Security](/organization). You must be signed in.

To create a team:
1. Open Team Security.
2. Click Create organization.
3. Enter a name and confirm.

You can also accept invitations from this page. Settings cannot create a team.`,
    keywords: [
      "team security",
      "team",
      "teams",
      "organization",
      "create organization",
      "create a team",
      "create team",
      "make a team",
      "new organization",
      "invite members",
      "invite teammate",
      "join organization",
      "join team",
      "org",
    ],
  },
  {
    id: "device-scanner",
    name: "Device Scanner",
    path: "/device-scanner",
    summary: "Scan your device for local security issues (sign-in required).",
    howTo:
      "Open Device Scanner in the left sidebar, or go to [Device Scanner](/device-scanner). Sign in first if asked.",
    keywords: [
      "device scanner",
      "scan device",
      "device scan",
      "local scan",
      "computer scan",
    ],
  },
  {
    id: "system-guardian",
    name: "System Guardian",
    path: "/system-guardian",
    summary:
      "Monitor system activity and local security events (sign-in required).",
    howTo:
      "Open System Guardian in the left sidebar, or go to [System Guardian](/system-guardian). Sign in first if asked.",
    keywords: [
      "system guardian",
      "guardian",
      "process monitor",
      "system monitor",
      "security timeline",
    ],
  },
  {
    id: "cyber-assistant",
    name: "Cyber Assistant",
    path: "/cyber-assistant",
    summary:
      "Ask cybersecurity questions and get guidance, including where to find tools in CyberGuard.",
    howTo:
      "Open Cyber Assistant from the floating button at the bottom-right, or from Cyber Assistant in the left sidebar. Type any security or CyberGuard question.",
    keywords: [
      "cyber assistant",
      "assistant",
      "chatbot",
      "ask a question",
      "help center",
      "what can you do",
      "what do you do",
    ],
  },
  {
    id: "news",
    name: "News",
    path: "/news",
    summary: "Read cybersecurity news curated for CyberGuard.",
    howTo: "Open News in the left sidebar, or go to [News](/news).",
    keywords: ["news", "cyber news", "security news", "headlines"],
  },
  {
    id: "reports",
    name: "Reports",
    path: "/reports",
    summary:
      "View CyberGuard reports and scan summaries (available from the sidebar).",
    howTo: "Open Reports in the left sidebar, or go to [Reports](/reports).",
    keywords: [
      "reports",
      "report",
      "scan history",
      "results history",
      "past scans",
      "summary",
    ],
  },
  {
    id: "settings",
    name: "Settings",
    path: "/settings",
    summary:
      "Manage your profile, account details, and alert notification preferences. Settings does not create teams.",
    howTo:
      "Open Settings in the left sidebar, or go to [Settings](/settings). Use this page for profile and notifications only. To create or join a team, use [Team Security](/organization).",
    keywords: [
      "settings",
      "preferences",
      "account settings",
      "profile",
      "change settings",
      "configuration",
      "notifications",
      "alert settings",
    ],
  },
  {
    id: "auth",
    name: "Login / Sign up",
    path: "/dashboard",
    summary:
      "Create an account or sign in with the Login and Sign Up buttons at the top of the left sidebar.",
    howTo: `Use the **Login** or **Sign Up** buttons at the top of the left sidebar (above the navigation).

After you sign in, the sidebar shows your email and a Log Out button. Account features use Supabase when it is configured in the app environment.`,
    keywords: [
      "login",
      "log in",
      "sign in",
      "signin",
      "sign up",
      "signup",
      "register",
      "create account",
      "logout",
      "log out",
      "account",
      "password reset",
    ],
  },
];

/** Topic id → related CyberGuard tools to suggest after a security answer. */
export const TOPIC_TOOL_LINKS: Record<string, string[]> = {
  phishing: ["email-scanner", "cyber-assistant"],
  smishing: ["email-scanner", "cyber-assistant"],
  vishing: ["cyber-assistant"],
  passwords: ["settings", "security-checker"],
  "password-manager": ["settings", "security-checker"],
  "2fa": ["settings", "security-checker"],
  links: ["website-tracker"],
  websites: ["website-tracker"],
  malware: ["security-checker", "website-tracker"],
  ransomware: ["security-checker", "reports"],
  attachments: ["email-scanner", "security-checker"],
  incident: ["email-scanner", "security-checker", "reports"],
  "data-breach": ["settings", "security-checker"],
  "identity-theft": ["reports", "settings"],
  wifi: ["security-checker"],
  vpn: ["security-checker"],
  updates: ["security-checker"],
  backups: ["security-checker"],
  "social-engineering": ["email-scanner", "cyber-assistant"],
  "romance-scam": ["cyber-assistant", "reports"],
  "gift-card-scam": ["cyber-assistant"],
  "qr-codes": ["website-tracker", "security-checker"],
  "social-media": ["security-checker", "settings"],
  privacy: ["settings", "security-checker"],
  browsing: ["website-tracker", "security-checker"],
  "device-security": ["security-checker", "settings"],
  "home-network": ["security-checker"],
  "kids-safety": ["cyber-assistant", "settings"],
  "work-security": ["team-security", "email-scanner", "security-checker"],
  "cookies-sessions": ["settings", "security-checker"],
  "cyberguard-tools": [
    "dashboard",
    "team-security",
    "email-scanner",
    "website-tracker",
    "security-checker",
  ],
};

export function featureById(id: string): PlatformFeature | undefined {
  return PLATFORM_FEATURES.find((feature) => feature.id === id);
}

export function formatFeatureRedirect(feature: PlatformFeature): string {
  return `${feature.name} — ${feature.summary}

${feature.howTo}`;
}

export function formatToolLinks(featureIds: string[]): string {
  const features = featureIds
    .map((id) => featureById(id))
    .filter((feature): feature is PlatformFeature => Boolean(feature));

  if (features.length === 0) {
    return "";
  }

  const lines = features.map(
    (feature) =>
      `${features.indexOf(feature) + 1}. [${feature.name}](${feature.path}) — ${feature.summary}`,
  );

  return `\n\nIn CyberGuard\n${lines.join("\n")}`;
}

export function platformCatalogReply(): string {
  const lines = PLATFORM_FEATURES.filter((f) => f.id !== "auth").map(
    (feature, index) =>
      `${index + 1}. [${feature.name}](${feature.path}) — ${feature.summary}`,
  );

  return `Here is what you can open in CyberGuard right now:

${lines.join("\n")}

Login / Sign up — use the buttons at the top of the left sidebar.

Tell me what you want to do (for example “scan an email” or “check a website”) and I will point you to the right place.`;
}
