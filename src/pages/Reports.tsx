import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowRightLeft,
  ArrowUpRight,
  AtSign,
  CalendarDays,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Download,
  FileSearch,
  FileText,
  Globe2,
  KeyRound,
  Laptop,
  Mail,
  Minus,
  Newspaper,
  Phone,
  Printer,
  Search,
  ShieldAlert,
  X,
  LockKeyhole,
} from "lucide-react";

import { listWebsiteHistory, type WebsiteHistoryEntry } from "../api/emailApi";
import { fetchNewsActivity } from "../api/newsApi";
import { useAuth } from "../context/AuthContext";
import { supabase } from "../lib/supabase";
import {
  SCAN_ACTIVITY_EVENT,
  listEmailScans,
  listSecurityScans,
  listSharedReportActivity,
  syncEmailScans,
  emailFindingFromClassification,
  type EmailScanEntry,
  type SecurityScanEntry,
} from "../lib/scanActivity";
import "./Reports.css";

type Category =
  | "websites"
  | "emails"
  | "files"
  | "passwords"
  | "phones"
  | "addresses"
  | "devices"
  | "news";

type Finding = "safe" | "suspicious" | "high" | "unverified" | "info";

type Range = "today" | "yesterday" | "7days" | "30days" | "all" | "custom";

type ReportSource =
  | "website_history"
  | "email_scanner"
  | "security_checker"
  | "device_scanner"
  | "news";

type ReportItem = {
  id: string;
  category: Category;
  title: string;
  detail: string;
  finding: Finding;
  occurredAt: string;
  source: ReportSource;
  score?: number;
  notes?: string[];
  passwordStrength?: "strong" | "moderate" | "weak";
};

const CATEGORIES: {
  id: Category;
  label: string;
  icon: typeof Globe2;
  description: string;
}[] = [
  {
    id: "websites",
    label: "Websites tracked",
    icon: Globe2,
    description: "Sites visited and evaluated by Website Tracker",
  },
  {
    id: "emails",
    label: "Emails scanned",
    icon: Mail,
    description: "Phishing and suspicious-message detection",
  },
  {
    id: "files",
    label: "Files scanned",
    icon: FileSearch,
    description: "Malware and file-integrity checks",
  },
  {
    id: "passwords",
    label: "Passwords checked",
    icon: KeyRound,
    description: "Password strength and exposure checks",
  },
  {
    id: "phones",
    label: "Phone numbers checked",
    icon: Phone,
    description: "Phone-number reputation lookups",
  },
  {
    id: "addresses",
    label: "Email addresses checked",
    icon: AtSign,
    description: "Email-address reputation and exposure",
  },
  {
    id: "devices",
    label: "Device scans",
    icon: Laptop,
    description: "Device Scanner security assessments",
  },
  {
    id: "news",
    label: "News articles viewed",
    icon: Newspaper,
    description: "Cybersecurity news reading activity",
  },
];

const FINDINGS: Record<Finding, string> = {
  safe: "No known threat",
  suspicious: "Suspicious",
  high: "High risk",
  unverified: "Unverified",
  info: "Informational",
};

const SOURCE_LABELS: Record<ReportSource, string> = {
  website_history: "Website Tracker history",
  email_scanner: "Email Scanner activity",
  security_checker: "Security Checker activity",
  device_scanner: "Device Scanner activity",
  news: "News reading activity",
};

const SECURITY_CATEGORY: Record<SecurityScanEntry["checkType"], Category> = {
  file: "files",
  password: "passwords",
  phone: "phones",
  email_address: "addresses",
  device: "devices",
};

const securitySourceOf = (
  checkType: SecurityScanEntry["checkType"],
): ReportSource => {
  if (checkType === "device") return "device_scanner";
  return "security_checker";
};

const riskOf = (risk: WebsiteHistoryEntry["risk_level"]): Finding => {
  if (risk === "HIGH_RISK") return "high";
  if (risk === "SUSPICIOUS") return "suspicious";
  if (risk === "NO_KNOWN_THREAT") return "safe";
  return "unverified";
};

const passwordStrengthOf = (
  entry: SecurityScanEntry,
): "strong" | "moderate" | "weak" => {
  const detail = entry.detail.toLowerCase();
  if (detail.includes("strong") || detail.includes("good")) return "strong";
  if (detail.includes("fair")) return "moderate";
  if (detail.includes("weak")) return "weak";
  if (entry.finding === "safe") return "strong";
  if (entry.finding === "suspicious") return "moderate";
  return "weak";
};

const websiteToReportItem = (entry: WebsiteHistoryEntry): ReportItem => ({
  id: `website-${entry.id}`,
  category: "websites",
  title: entry.domain || entry.url,
  detail: entry.url,
  finding: riskOf(entry.risk_level),
  occurredAt: entry.visited_at,
  source: "website_history",
  score:
    typeof entry.risk_score === "number"
      ? Math.round(entry.risk_score)
      : undefined,
  notes: [
    ...(entry.threat_types ?? []).map(
      (t) => `Threat type: ${t.replaceAll("_", " ")}`,
    ),
    ...(entry.explanation ?? []),
  ],
});

const emailToReportItem = (entry: EmailScanEntry): ReportItem => ({
  id: `email-${entry.id}`,
  category: "emails",
  title: entry.title,
  detail: entry.detail.startsWith("Sender:")
    ? entry.detail
    : `Sender: ${entry.detail}`,
  finding: entry.finding,
  occurredAt: entry.occurredAt,
  source: "email_scanner",
});

const securityToReportItem = (entry: SecurityScanEntry): ReportItem => {
  const category = SECURITY_CATEGORY[entry.checkType];
  const isPassword = entry.checkType === "password";

  return {
    id: `security-${entry.id}`,
    category,
    title: entry.title,
    detail: isPassword ? "Password value not stored in report" : entry.detail,
    finding: entry.finding,
    occurredAt: entry.occurredAt,
    source: securitySourceOf(entry.checkType),
    passwordStrength: isPassword ? passwordStrengthOf(entry) : undefined,
    notes: isPassword
      ? [
          `Password strength: ${entry.detail}`,
          "The original password is not stored.",
        ]
      : undefined,
  };
};

const dateText = (iso: string) =>
  new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });

const dayStart = (date: Date) =>
  new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();

const inRange = (iso: string, range: Range, start: string, end: string) => {
  const value = Date.parse(iso);

  if (!Number.isFinite(value)) return false;
  if (range === "all") return true;

  const today = dayStart(new Date());

  if (range === "today") return value >= today;
  if (range === "yesterday") {
    return value >= today - 86400000 && value < today;
  }
  if (range === "7days") return value >= today - 6 * 86400000;
  if (range === "30days") return value >= today - 29 * 86400000;
  if (!start || !end) return false;

  return (
    value >= new Date(`${start}T00:00:00`).getTime() &&
    value <= new Date(`${end}T23:59:59.999`).getTime()
  );
};

const periodLabelOf = (range: Range, start: string, end: string) =>
  range === "today"
    ? "Today"
    : range === "yesterday"
      ? "Yesterday"
      : range === "7days"
        ? "Last 7 days"
        : range === "30days"
          ? "Last 30 days"
          : range === "all"
            ? "All time"
            : `${start || "Start"} to ${end || "End"}`;

type ComparePreset =
  | "today_vs_yesterday"
  | "7_vs_prior"
  | "30_vs_prior"
  | "custom";

type DateWindow = {
  startMs: number;
  endMs: number;
  label: string;
  detail: string;
};

const DAY_MS = 86400000;

const startOfDaysAgo = (daysAgo: number, from = new Date()) =>
  new Date(
    from.getFullYear(),
    from.getMonth(),
    from.getDate() - daysAgo,
  ).getTime();

const endOfDayMs = (startMs: number) => startMs + DAY_MS - 1;

const toDateInput = (ms: number) => {
  const date = new Date(ms);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
};

const shortDate = (ms: number) =>
  new Date(ms).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });

const windowDetail = (startMs: number, endMs: number) =>
  `${shortDate(startMs)} – ${shortDate(endMs)}`;

const parseDateStart = (value: string) =>
  value ? new Date(`${value}T00:00:00`).getTime() : Number.NaN;

const parseDateEnd = (value: string) =>
  value ? new Date(`${value}T23:59:59.999`).getTime() : Number.NaN;

const inWindow = (iso: string, startMs: number, endMs: number) => {
  const value = Date.parse(iso);
  return Number.isFinite(value) && value >= startMs && value <= endMs;
};

const rollingWindows = (days: number) => {
  const laterStartMs = startOfDaysAgo(days - 1);
  const earlierEndStartMs = startOfDaysAgo(days);
  const earlierStartMs = startOfDaysAgo(days * 2 - 1);
  const endOfToday = endOfDayMs(startOfDaysAgo(0));

  return {
    earlier: {
      startMs: earlierStartMs,
      endMs: endOfDayMs(earlierEndStartMs),
      label: `Prior ${days} days`,
      detail: windowDetail(earlierStartMs, earlierEndStartMs),
    },
    later: {
      startMs: laterStartMs,
      endMs: endOfToday,
      label: `Last ${days} days`,
      detail: windowDetail(laterStartMs, endOfToday),
    },
  };
};

const compareWindowsOf = (
  preset: ComparePreset,
  earlierStart: string,
  earlierEnd: string,
  laterStart: string,
  laterEnd: string,
): { earlier: DateWindow; later: DateWindow } => {
  const today = startOfDaysAgo(0);
  const yesterday = startOfDaysAgo(1);

  if (preset === "today_vs_yesterday") {
    return {
      earlier: {
        startMs: yesterday,
        endMs: endOfDayMs(yesterday),
        label: "Yesterday",
        detail: shortDate(yesterday),
      },
      later: {
        startMs: today,
        endMs: endOfDayMs(today),
        label: "Today",
        detail: shortDate(today),
      },
    };
  }

  if (preset === "7_vs_prior") return rollingWindows(7);
  if (preset === "30_vs_prior") return rollingWindows(30);

  const earlierStartMs = parseDateStart(earlierStart);
  const earlierEndMs = parseDateEnd(earlierEnd);
  const laterStartMs = parseDateStart(laterStart);
  const laterEndMs = parseDateEnd(laterEnd);
  const earlierValid =
    Number.isFinite(earlierStartMs) && Number.isFinite(earlierEndMs);
  const laterValid =
    Number.isFinite(laterStartMs) && Number.isFinite(laterEndMs);

  return {
    earlier: {
      startMs: earlierValid ? earlierStartMs : Number.NaN,
      endMs: earlierValid ? earlierEndMs : Number.NaN,
      label: "Earlier period",
      detail: earlierValid
        ? windowDetail(earlierStartMs, earlierEndMs)
        : "Pick dates",
    },
    later: {
      startMs: laterValid ? laterStartMs : Number.NaN,
      endMs: laterValid ? laterEndMs : Number.NaN,
      label: "Later period",
      detail: laterValid
        ? windowDetail(laterStartMs, laterEndMs)
        : "Pick dates",
    },
  };
};

const defaultComparePreset = (current: Range): ComparePreset => {
  if (current === "today" || current === "yesterday") {
    return "today_vs_yesterday";
  }
  if (current === "7days") return "7_vs_prior";
  return "30_vs_prior";
};

type ReportMetrics = {
  total: number;
  safe: number;
  suspicious: number;
  high: number;
  unverified: number;
  info: number;
  flagged: number;
  avgWebsiteScore: number | null;
  byCategory: Record<
    Category,
    {
      total: number;
      flagged: number;
    }
  >;
};

const emptyCategoryMetrics = (): ReportMetrics["byCategory"] =>
  Object.fromEntries(
    CATEGORIES.map(({ id }) => [id, { total: 0, flagged: 0 }]),
  ) as ReportMetrics["byCategory"];

const metricsOf = (items: ReportItem[]): ReportMetrics => {
  const byCategory = emptyCategoryMetrics();
  let safe = 0;
  let suspicious = 0;
  let high = 0;
  let unverified = 0;
  let info = 0;
  let scoreSum = 0;
  let scoreCount = 0;

  for (const item of items) {
    byCategory[item.category].total += 1;
    if (item.finding === "high" || item.finding === "suspicious") {
      byCategory[item.category].flagged += 1;
    }
    if (item.finding === "safe") safe += 1;
    else if (item.finding === "suspicious") suspicious += 1;
    else if (item.finding === "high") high += 1;
    else if (item.finding === "unverified") unverified += 1;
    else if (item.finding === "info") info += 1;
    if (item.category === "websites" && typeof item.score === "number") {
      scoreSum += item.score;
      scoreCount += 1;
    }
  }

  return {
    total: items.length,
    safe,
    suspicious,
    high,
    unverified,
    info,
    flagged: suspicious + high,
    avgWebsiteScore:
      scoreCount > 0 ? Math.round(scoreSum / scoreCount) : null,
    byCategory,
  };
};

const dedupeReportItems = (items: ReportItem[]) => {
  const seen = new Set<string>();
  return items.filter((item) => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });
};

const deltaOf = (later: number, earlier: number) => later - earlier;

const formatSigned = (value: number) =>
  value > 0 ? `+${value}` : String(value);

type TrendTone = "better" | "worse" | "neutral";

const riskTone = (delta: number): TrendTone => {
  if (delta < 0) return "better";
  if (delta > 0) return "worse";
  return "neutral";
};

const TrendIcon = ({ tone }: { tone: TrendTone }) => {
  if (tone === "better") return <ArrowDownRight size={14} />;
  if (tone === "worse") return <ArrowUpRight size={14} />;
  return <Minus size={14} />;
};

const csvEscape = (value: unknown) =>
  `"${String(value ?? "").replaceAll('"', '""')}"`;

function download(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();

  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function Reports() {
  const { session } = useAuth();
  return <ReportsContent key={session?.user.id ?? "guest"} />;
}

function ReportsContent() {
  const { session } = useAuth();
  const [searchParams] = useSearchParams();
  const userId = session?.user.id;
  const memberId = searchParams.get("member");
  const viewedUserId = memberId || userId;
  const viewingMember = Boolean(memberId && memberId !== userId);
  const organizationId = searchParams.get("org");

  const [websites, setWebsites] = useState<ReportItem[]>([]);
  const [emails, setEmails] = useState<ReportItem[]>([]);
  const [security, setSecurity] = useState<ReportItem[]>([]);
  const [news, setNews] = useState<ReportItem[]>([]);
  const [loadError, setLoadError] = useState("");
  const [loading, setLoading] = useState(Boolean(session?.access_token));
  const [memberProfile, setMemberProfile] = useState<{
    name: string;
    email: string;
  } | null>(null);

  const [range, setRange] = useState<Range>("today");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [compareMode, setCompareMode] = useState(false);
  const [comparePreset, setComparePreset] =
    useState<ComparePreset>("30_vs_prior");
  const [compareEarlierStart, setCompareEarlierStart] = useState("");
  const [compareEarlierEnd, setCompareEarlierEnd] = useState("");
  const [compareLaterStart, setCompareLaterStart] = useState("");
  const [compareLaterEnd, setCompareLaterEnd] = useState("");
  const [search, setSearch] = useState("");

  const [selectedCategory, setSelectedCategory] = useState<Category | "all">(
    "all",
  );

  const [expanded, setExpanded] = useState<string | null>(null);

  const allItems = useMemo(
    () =>
      [...websites, ...emails, ...security, ...news].sort(
        (a, b) => Date.parse(b.occurredAt) - Date.parse(a.occurredAt),
      ),
    [websites, emails, security, news],
  );

  const applySelfLocalActivity = (
    shared: Awaited<ReturnType<typeof listSharedReportActivity>> = [],
  ) => {
    if (!userId || viewingMember) return;

    const localEmails = listEmailScans(userId).map(emailToReportItem);
    const localSecurity = listSecurityScans(userId).map(securityToReportItem);
    const sharedEmails = shared
      .filter((entry) => entry.kind === "email")
      .map((entry) => emailToReportItem(entry));
    const sharedSecurity = shared
      .filter((entry) => entry.kind === "security")
      .map((entry) => securityToReportItem(entry));

    setEmails(dedupeReportItems([...localEmails, ...sharedEmails]));
    setSecurity(dedupeReportItems([...localSecurity, ...sharedSecurity]));
  };

  const refreshLocalActivity = () => {
    if (!userId) {
      setEmails([]);
      setSecurity([]);
      return;
    }
    if (viewingMember) return;

    applySelfLocalActivity();
    void listSharedReportActivity(userId)
      .then((shared) => {
        if (!viewingMember) applySelfLocalActivity(shared);
      })
      .catch((error) => {
        console.warn(
          "CyberGuard: couldn't load shared report activity.",
          error instanceof Error ? error.message : error,
        );
      });
  };

  // Email Scanner + Security Checker + Device Scanner (local + shared).
  useEffect(() => {
    if (viewingMember) {
      setEmails([]);
      setSecurity([]);
      return;
    }

    refreshLocalActivity();
    if (userId) void syncEmailScans(userId).then(refreshLocalActivity);
    const onActivity = () => refreshLocalActivity();
    window.addEventListener(SCAN_ACTIVITY_EVENT, onActivity);
    window.addEventListener("storage", onActivity);
    window.addEventListener("focus", onActivity);
    return () => {
      window.removeEventListener(SCAN_ACTIVITY_EVENT, onActivity);
      window.removeEventListener("storage", onActivity);
      window.removeEventListener("focus", onActivity);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- refresh when user changes
  }, [userId, viewingMember]);

  // Website Tracker history + news reading activity (+ member org data).
  useEffect(() => {
    if (!session?.access_token || !userId || !viewedUserId) {
      setWebsites([]);
      setNews([]);
      setMemberProfile(null);
      setLoading(false);
      return;
    }

    let cancelled = false;
    let requestInFlight = false;

    async function load() {
      if (cancelled || document.hidden || requestInFlight) return;
      requestInFlight = true;

      try {
        const [
          history,
          newsActivity,
          memberEmails,
          memberActivity,
          member,
          profile,
          sharedSelf,
        ] =
          viewingMember
            ? await Promise.all([
                supabase!
                  .from("website_history")
                  .select(
                    "id,url,domain,risk_score,risk_level,source,threat_types,explanation,visited_at",
                  )
                  .eq("user_id", viewedUserId)
                  .order("visited_at", { ascending: false })
                  .limit(1000),
                supabase!
                  .from("news_activity")
                  .select("article,read,updated_at")
                  .eq("user_id", viewedUserId)
                  .eq("read", true)
                  .order("updated_at", { ascending: false })
                  .limit(1000),
                supabase!
                  .from("email_scans")
                  .select(
                    "id,sender,subject,classification,scanned_at",
                  )
                  .eq("user_id", viewedUserId)
                  .order("scanned_at", { ascending: false })
                  .limit(1000),
                supabase!
                  .from("cg_report_activity")
                  .select("id,kind,payload,occurred_at")
                  .eq("user_id", viewedUserId)
                  .order("occurred_at", { ascending: false })
                  .limit(1000),
                supabase!
                  .from("cg_memberships")
                  .select("email")
                  .eq("organization_id", organizationId)
                  .eq("user_id", viewedUserId)
                  .maybeSingle(),
                supabase!
                  .from("profiles")
                  .select("first_name,last_name,username")
                  .eq("id", viewedUserId)
                  .maybeSingle(),
                Promise.resolve({ data: [] as Awaited<
                  ReturnType<typeof listSharedReportActivity>
                >, error: null }),
              ])
            : await Promise.all([
                listWebsiteHistory(1000, session?.access_token ?? "")
                  .then((data) => ({ data, error: null as Error | null }))
                  .catch((error: unknown) => ({
                    data: [] as Awaited<ReturnType<typeof listWebsiteHistory>>,
                    error:
                      error instanceof Error
                        ? error
                        : new Error("Unable to load website history."),
                  })),
                fetchNewsActivity(userId!)
                  .then((data) => ({ data, error: null as Error | null }))
                  .catch((error: unknown) => ({
                    data: [] as Awaited<ReturnType<typeof fetchNewsActivity>>,
                    error:
                      error instanceof Error
                        ? error
                        : new Error("Unable to load news activity."),
                  })),
                Promise.resolve({ data: [], error: null }),
                Promise.resolve({ data: [], error: null }),
                Promise.resolve({ data: null, error: null }),
                Promise.resolve({ data: null, error: null }),
                listSharedReportActivity(userId!)
                  .then((data) => ({ data, error: null as Error | null }))
                  .catch((error: unknown) => ({
                    data: [] as Awaited<
                      ReturnType<typeof listSharedReportActivity>
                    >,
                    error:
                      error instanceof Error
                        ? error
                        : new Error("Unable to load shared activity."),
                  })),
              ]);

        const failures = [
          history.error,
          newsActivity.error,
          memberEmails.error,
          memberActivity.error,
          member.error,
          profile.error,
          sharedSelf.error,
        ].filter(Boolean);
        if (failures.length && viewingMember) {
          throw failures[0];
        }

        if (cancelled) return;

        setWebsites((history.data ?? []).map(websiteToReportItem));
        if (viewingMember) {
          setMemberProfile({
            name: [profile.data?.first_name, profile.data?.last_name]
              .filter(Boolean)
              .join(" ") || profile.data?.username || "",
            email: member.data?.email ?? "Member",
          });
          setEmails(
            [
              ...(memberEmails.data ?? []).map((entry) =>
                emailToReportItem({
                  id: entry.id,
                  kind: "email",
                  title: entry.subject ?? "(No subject)",
                  detail: entry.sender,
                  finding: emailFindingFromClassification(entry.classification),
                  occurredAt: entry.scanned_at,
                }),
              ),
              ...(memberActivity.data ?? [])
                .filter(
                  (entry) =>
                    entry.kind === "email" &&
                    !(memberEmails.data ?? []).some(
                      (email) => email.id === entry.id,
                    ),
                )
                .map((entry) => {
                  const payload = entry.payload as Record<string, unknown>;
                  return emailToReportItem({
                    id: entry.id,
                    kind: "email",
                    title: String(payload.subject ?? "(No subject)"),
                    detail: String(payload.sender ?? "Unknown sender"),
                    finding: emailFindingFromClassification(
                      String(payload.classification ?? "UNKNOWN"),
                    ),
                    occurredAt: entry.occurred_at,
                  });
                }),
            ],
          );
          setSecurity(
            (memberActivity.data ?? [])
              .filter((entry) => entry.kind !== "email")
              .map((entry) => {
                const payload = entry.payload as Record<string, unknown>;
                return securityToReportItem({
                  id: entry.id,
                  kind: "security",
                  checkType:
                    entry.kind === "device"
                      ? "device"
                      : (String(payload.checkType) as SecurityScanEntry["checkType"]),
                  title: String(payload.title ?? "Security check"),
                  detail: String(payload.detail ?? ""),
                  finding: (payload.finding as SecurityScanEntry["finding"]) ?? "unverified",
                  occurredAt: entry.occurred_at,
                });
              }),
          );
        } else {
          applySelfLocalActivity(sharedSelf.data ?? []);
        }
        setNews(
          (newsActivity.data ?? [])
            .filter((item) => item.read && item.article)
            .map((item) => ({
              id: `news-${item.article.id}`,
              category: "news" as const,
              title: item.article.title,
              detail: item.article.source
                ? `Article from ${item.article.source}`
                : "Cybersecurity article viewed",
              finding: "info" as const,
              occurredAt:
                item.updated_at ||
                item.article.published_at ||
                new Date().toISOString(),
              source: "news" as const,
              notes: item.article.summary ? [item.article.summary] : undefined,
            })),
        );

        if (!viewingMember && failures.length) {
          setLoadError(
            failures
              .map((error) =>
                error instanceof Error ? error.message : String(error),
              )
              .join(" · "),
          );
        } else {
          setLoadError("");
        }
      } catch (error) {
        if (!cancelled) {
          setLoadError(
            error instanceof Error
              ? error.message
              : "Unable to load report activity.",
          );
        }
      } finally {
        requestInFlight = false;
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void load();

    const timer = window.setInterval(() => void load(), 30000);
    const onVisibility = () => {
      if (!document.hidden) void load();
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- refresh when session changes
  }, [session?.access_token, userId, viewedUserId, viewingMember]);

  const items = useMemo(
    () =>
      allItems.filter((item) => inRange(item.occurredAt, range, start, end)),
    [allItems, range, start, end],
  );

  const compareWindows = useMemo(
    () =>
      compareWindowsOf(
        comparePreset,
        compareEarlierStart,
        compareEarlierEnd,
        compareLaterStart,
        compareLaterEnd,
      ),
    [
      comparePreset,
      compareEarlierStart,
      compareEarlierEnd,
      compareLaterStart,
      compareLaterEnd,
    ],
  );

  const earlierItems = useMemo(
    () =>
      Number.isFinite(compareWindows.earlier.startMs)
        ? allItems.filter((item) =>
            inWindow(
              item.occurredAt,
              compareWindows.earlier.startMs,
              compareWindows.earlier.endMs,
            ),
          )
        : [],
    [allItems, compareWindows],
  );

  const laterItems = useMemo(
    () =>
      Number.isFinite(compareWindows.later.startMs)
        ? allItems.filter((item) =>
            inWindow(
              item.occurredAt,
              compareWindows.later.startMs,
              compareWindows.later.endMs,
            ),
          )
        : [],
    [allItems, compareWindows],
  );

  const counts = useMemo(() => metricsOf(items), [items]);
  const earlierMetrics = useMemo(() => metricsOf(earlierItems), [earlierItems]);
  const laterMetrics = useMemo(() => metricsOf(laterItems), [laterItems]);

  const flagged = counts.flagged;

  const shown = useMemo(
    () =>
      items.filter((item) => {
        if (selectedCategory !== "all" && item.category !== selectedCategory) {
          return false;
        }

        const q = search.trim().toLowerCase();

        return (
          !q ||
          [
            item.title,
            item.detail,
            FINDINGS[item.finding],
            ...(item.notes ?? []),
          ].some((value) => value.toLowerCase().includes(q))
        );
      }),
    [items, selectedCategory, search],
  );

  const periodLabel = periodLabelOf(range, start, end);
  const earlierLabel = compareWindows.earlier.label;
  const laterLabel = compareWindows.later.label;
  const earlierDetail = compareWindows.earlier.detail;
  const laterDetail = compareWindows.later.detail;
  const compareHasData =
    earlierMetrics.total > 0 || laterMetrics.total > 0;

  const compareDeltas = useMemo(() => {
    const flaggedDelta = deltaOf(laterMetrics.flagged, earlierMetrics.flagged);
    const highDelta = deltaOf(laterMetrics.high, earlierMetrics.high);
    const suspiciousDelta = deltaOf(
      laterMetrics.suspicious,
      earlierMetrics.suspicious,
    );
    const safeDelta = deltaOf(laterMetrics.safe, earlierMetrics.safe);
    const totalDelta = deltaOf(laterMetrics.total, earlierMetrics.total);
    const scoreDelta =
      laterMetrics.avgWebsiteScore !== null &&
      earlierMetrics.avgWebsiteScore !== null
        ? deltaOf(laterMetrics.avgWebsiteScore, earlierMetrics.avgWebsiteScore)
        : null;

    let verdict: "improved" | "declined" | "stable" | "empty" = "stable";
    let reason: "flagged" | "score" | "none" | "empty" = "none";
    if (earlierMetrics.total === 0 && laterMetrics.total === 0) {
      verdict = "empty";
      reason = "empty";
    } else if (highDelta < 0 || (highDelta === 0 && flaggedDelta < 0)) {
      verdict = "improved";
      reason = "flagged";
    } else if (highDelta > 0 || (highDelta === 0 && flaggedDelta > 0)) {
      verdict = "declined";
      reason = "flagged";
    } else if (
      scoreDelta !== null &&
      scoreDelta !== 0 &&
      highDelta === 0 &&
      flaggedDelta === 0
    ) {
      verdict = scoreDelta < 0 ? "improved" : "declined";
      reason = "score";
    }

    return {
      flaggedDelta,
      highDelta,
      suspiciousDelta,
      safeDelta,
      totalDelta,
      scoreDelta,
      verdict,
      reason,
    };
  }, [earlierMetrics, laterMetrics]);

  const exportRows = shown.map((item) => ({
    category: item.category,
    title: item.title,
    detail: item.detail,
    finding: FINDINGS[item.finding],
    score: item.score ?? "",
    date: item.occurredAt,
    data_source: SOURCE_LABELS[item.source],
    notes: (item.notes ?? []).join("; "),
  }));

  const exportJson = () => {
    if (compareMode) {
      download(
        "cyberguard-security-compare.json",
        JSON.stringify(
          {
            mode: "compare",
            earlier_period: earlierLabel,
            later_period: laterLabel,
            generated_at: new Date().toISOString(),
            verdict: compareDeltas.verdict,
            earlier: earlierMetrics,
            later: laterMetrics,
            deltas: {
              total: compareDeltas.totalDelta,
              safe: compareDeltas.safeDelta,
              suspicious: compareDeltas.suspiciousDelta,
              high: compareDeltas.highDelta,
              flagged: compareDeltas.flaggedDelta,
              avg_website_score: compareDeltas.scoreDelta,
            },
          },
          null,
          2,
        ),
        "application/json",
      );
      return;
    }

    download(
      "cyberguard-security-report.json",
      JSON.stringify(
        {
          period: periodLabel,
          generated_at: new Date().toISOString(),
          activities: exportRows,
        },
        null,
        2,
      ),
      "application/json",
    );
  };

  const exportCsv = () => {
    if (compareMode) {
      const headers = [
        "metric",
        "earlier",
        "later",
        "delta",
        "earlier_period",
        "later_period",
      ] as const;

      const rows = [
        ["total", earlierMetrics.total, laterMetrics.total, compareDeltas.totalDelta],
        ["safe", earlierMetrics.safe, laterMetrics.safe, compareDeltas.safeDelta],
        [
          "suspicious",
          earlierMetrics.suspicious,
          laterMetrics.suspicious,
          compareDeltas.suspiciousDelta,
        ],
        ["high", earlierMetrics.high, laterMetrics.high, compareDeltas.highDelta],
        [
          "flagged",
          earlierMetrics.flagged,
          laterMetrics.flagged,
          compareDeltas.flaggedDelta,
        ],
        [
          "avg_website_score",
          earlierMetrics.avgWebsiteScore ?? "",
          laterMetrics.avgWebsiteScore ?? "",
          compareDeltas.scoreDelta ?? "",
        ],
        ...CATEGORIES.flatMap(({ id, label }) => {
          const earlier = earlierMetrics.byCategory[id];
          const later = laterMetrics.byCategory[id];
          return [
            [
              `${label} total`,
              earlier.total,
              later.total,
              deltaOf(later.total, earlier.total),
            ],
            [
              `${label} flagged`,
              earlier.flagged,
              later.flagged,
              deltaOf(later.flagged, earlier.flagged),
            ],
          ];
        }),
      ];

      download(
        "cyberguard-security-compare.csv",
        [
          headers.join(","),
          ...rows.map((row) =>
            [
              csvEscape(row[0]),
              csvEscape(row[1]),
              csvEscape(row[2]),
              csvEscape(row[3]),
              csvEscape(earlierLabel),
              csvEscape(laterLabel),
            ].join(","),
          ),
        ].join("\r\n"),
        "text/csv;charset=utf-8",
      );
      return;
    }

    const headers = [
      "category",
      "title",
      "detail",
      "finding",
      "score",
      "date",
      "data_source",
      "notes",
    ] as const;

    download(
      "cyberguard-security-report.csv",
      [
        headers.join(","),
        ...exportRows.map((row) =>
          headers.map((key) => csvEscape(row[key])).join(","),
        ),
      ].join("\r\n"),
      "text/csv;charset=utf-8",
    );
  };

  const enterCompareMode = () => {
    // Prefer a window that can include older scans when the current view is empty.
    const preset =
      range === "custom"
        ? "custom"
        : items.length === 0
          ? "30_vs_prior"
          : defaultComparePreset(range);
    setComparePreset(preset);

    if (range === "custom" && start && end) {
      const startMs = parseDateStart(start);
      const endMs = parseDateEnd(end);
      if (Number.isFinite(startMs) && Number.isFinite(endMs) && endMs >= startMs) {
        const startDay = dayStart(new Date(startMs));
        const endDay = dayStart(new Date(endMs));
        const spanDays = Math.max(
          1,
          Math.round((endDay - startDay) / DAY_MS) + 1,
        );
        const priorEnd = startOfDaysAgo(
          Math.round((dayStart(new Date()) - startDay) / DAY_MS) + 1,
        );
        const priorStart = startOfDaysAgo(
          Math.round((dayStart(new Date()) - startDay) / DAY_MS) + spanDays,
        );
        setCompareEarlierStart(toDateInput(priorStart));
        setCompareEarlierEnd(toDateInput(priorEnd));
        setCompareLaterStart(start);
        setCompareLaterEnd(end);
      }
    } else if (preset === "custom") {
      setCompareLaterStart(toDateInput(startOfDaysAgo(29)));
      setCompareLaterEnd(toDateInput(startOfDaysAgo(0)));
      setCompareEarlierStart(toDateInput(startOfDaysAgo(59)));
      setCompareEarlierEnd(toDateInput(startOfDaysAgo(30)));
    }

    setCompareMode(true);
  };

  const getResultLabel = (item: ReportItem) => {
    if (item.category === "passwords" && item.passwordStrength) {
      return {
        strong: "Strong",
        moderate: "Moderate",
        weak: "Weak",
      }[item.passwordStrength];
    }

    return FINDINGS[item.finding];
  };

  const getResultClass = (item: ReportItem) => {
    if (item.category === "passwords" && item.passwordStrength) {
      return {
        strong: "safe",
        moderate: "suspicious",
        weak: "high",
      }[item.passwordStrength];
    }

    return item.finding;
  };

  if (!session) {
    return (
      <main className="reports-page">
        <div className="report-guest-container">
          <div className="report-guest-icon">
            <LockKeyhole size={32} />
          </div>

          <h2>Sign in to view your security reports</h2>

          <p>
            CyberGuard saves your security activity and scan history to your
            account. Log in or create an account to view your reports.
          </p>

          <div className="report-guest-actions">
            <button
              className="report-guest-button"
              onClick={() => window.location.assign("/login")}
            >
              Log In
            </button>

            <button
              className="report-guest-button secondary"
              onClick={() => window.location.assign("/signup")}
            >
              Create Account
            </button>
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="reports-page">
      <header className="report-topbar no-print">
        <div>
          <h1>{viewingMember ? "Member security reports" : "Security reports"}</h1>
          {viewingMember && memberProfile && (
            <div className="report-member-identity">
              <strong>{memberProfile.name || memberProfile.email}</strong>
              <span>{memberProfile.email}</span>
            </div>
          )}
          <p>
            {loading
              ? "Loading activity…"
              : compareMode
                ? `Comparing ${earlierDetail} → ${laterDetail}`
                : flagged
                  ? `${items.length} activities · ${flagged} flagged`
                  : `${items.length} activities in this period`}
          </p>
        </div>

        <div className="report-toolbar">
          {!compareMode && (
            <>
              <label className="report-period">
                <CalendarDays size={16} />
                <select
                  value={range}
                  aria-label="Report period"
                  onChange={(event) => setRange(event.target.value as Range)}
                >
                  <option value="today">Today</option>
                  <option value="yesterday">Yesterday</option>
                  <option value="7days">Last 7 days</option>
                  <option value="30days">Last 30 days</option>
                  <option value="all">All time</option>
                  <option value="custom">Custom range</option>
                </select>
              </label>

              {range === "custom" && (
                <div className="report-custom-dates">
                  <input
                    type="date"
                    aria-label="From date"
                    value={start}
                    onChange={(event) => setStart(event.target.value)}
                  />
                  <span>to</span>
                  <input
                    type="date"
                    aria-label="To date"
                    min={start || undefined}
                    value={end}
                    onChange={(event) => setEnd(event.target.value)}
                  />
                </div>
              )}
            </>
          )}

          <div className="report-top-actions">
            <button
              type="button"
              className={compareMode ? "active" : undefined}
              onClick={() =>
                compareMode ? setCompareMode(false) : enterCompareMode()
              }
            >
              <ArrowRightLeft size={16} />
              {compareMode ? "Exit compare" : "Compare"}
            </button>
            <button type="button" onClick={() => window.print()}>
              <Printer size={16} />
              Print
            </button>
            <button type="button" onClick={exportCsv}>
              <Download size={16} />
              CSV
            </button>
            <button type="button" onClick={exportJson}>
              <Download size={16} />
              JSON
            </button>
          </div>
        </div>
      </header>

      {loadError && (
        <div className="report-notice report-error">
          Some report activity could not be loaded: {loadError}
        </div>
      )}

      <article className="report-document">
        <section className="report-document-header">
          <div>
            <h2>
              {compareMode
                ? `${earlierLabel} vs ${laterLabel}`
                : periodLabel}
            </h2>
            <p>
              {compareMode
                ? `${earlierDetail} → ${laterDetail} · Generated ${new Date().toLocaleString()}`
                : `Generated ${new Date().toLocaleString()}`}
            </p>
          </div>
        </section>

        {compareMode ? (
          <>
            <section className="report-section no-print">
              <div className="report-section-title">
                <h3>Periods</h3>
              </div>
              <div className="report-compare-periods">
                <label className="report-period">
                  <CalendarDays size={16} />
                  <select
                    value={comparePreset}
                    aria-label="Compare preset"
                    onChange={(event) =>
                      setComparePreset(event.target.value as ComparePreset)
                    }
                  >
                    <option value="today_vs_yesterday">
                      Today vs yesterday
                    </option>
                    <option value="7_vs_prior">
                      Last 7 days vs prior 7
                    </option>
                    <option value="30_vs_prior">
                      Last 30 days vs prior 30
                    </option>
                    <option value="custom">Custom ranges</option>
                  </select>
                </label>

                <div className="report-compare-window-labels">
                  <div>
                    <strong>{earlierLabel}</strong>
                    <span>{earlierDetail}</span>
                  </div>
                  <div>
                    <strong>{laterLabel}</strong>
                    <span>{laterDetail}</span>
                  </div>
                </div>

                {comparePreset === "custom" && (
                  <div className="report-compare-custom-grid">
                    <div className="report-period-block">
                      <span className="report-period-label">Earlier</span>
                      <div className="report-custom-dates">
                        <input
                          type="date"
                          aria-label="Earlier from date"
                          value={compareEarlierStart}
                          onChange={(event) =>
                            setCompareEarlierStart(event.target.value)
                          }
                        />
                        <span>to</span>
                        <input
                          type="date"
                          aria-label="Earlier to date"
                          min={compareEarlierStart || undefined}
                          value={compareEarlierEnd}
                          onChange={(event) =>
                            setCompareEarlierEnd(event.target.value)
                          }
                        />
                      </div>
                    </div>
                    <div className="report-period-block">
                      <span className="report-period-label">Later</span>
                      <div className="report-custom-dates">
                        <input
                          type="date"
                          aria-label="Later from date"
                          value={compareLaterStart}
                          onChange={(event) =>
                            setCompareLaterStart(event.target.value)
                          }
                        />
                        <span>to</span>
                        <input
                          type="date"
                          aria-label="Later to date"
                          min={compareLaterStart || undefined}
                          value={compareLaterEnd}
                          onChange={(event) =>
                            setCompareLaterEnd(event.target.value)
                          }
                        />
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </section>

            <section className="report-section">
              <div className="report-section-title">
                <h3>Security change</h3>
              </div>

              <div
                className={`report-compare-verdict ${compareDeltas.verdict}`}
              >
                <strong>
                  {compareDeltas.verdict === "improved"
                    ? "Security improved"
                    : compareDeltas.verdict === "declined"
                      ? "Security declined"
                      : compareDeltas.verdict === "empty"
                        ? "Not enough activity to compare"
                        : "Security held steady"}
                </strong>
                <p>
                  {compareDeltas.verdict === "empty"
                    ? "Neither period has scanned activity yet. Try Last 30 days vs prior 30, or choose custom dates that cover your history."
                    : compareDeltas.reason === "score" &&
                        compareDeltas.verdict === "improved"
                      ? `Average website risk score dropped in ${laterLabel.toLowerCase()} (${laterDetail}) versus ${earlierLabel.toLowerCase()} (${earlierDetail}).`
                      : compareDeltas.reason === "score" &&
                          compareDeltas.verdict === "declined"
                        ? `Average website risk score rose in ${laterLabel.toLowerCase()} (${laterDetail}) versus ${earlierLabel.toLowerCase()} (${earlierDetail}).`
                        : compareDeltas.verdict === "improved"
                          ? `Fewer risk signals in ${laterLabel.toLowerCase()} (${laterDetail}) than ${earlierLabel.toLowerCase()} (${earlierDetail}).`
                          : compareDeltas.verdict === "declined"
                            ? `More risk signals in ${laterLabel.toLowerCase()} (${laterDetail}) than ${earlierLabel.toLowerCase()} (${earlierDetail}).`
                            : "Flagged and high-risk counts look similar across both periods."}
                </p>
              </div>

              {!compareHasData && (
                <div className="report-compare-empty-tip">
                  Tip: your stored activity may fall outside today/yesterday.
                  Switch the preset above to include older scans.
                </div>
              )}

              <div className="report-compare-metrics">
                {(
                  [
                    {
                      key: "total",
                      label: "Total",
                      icon: Activity,
                      earlier: earlierMetrics.total,
                      later: laterMetrics.total,
                      delta: compareDeltas.totalDelta,
                      tone: "neutral" as TrendTone,
                    },
                    {
                      key: "safe",
                      label: "Safe",
                      icon: CheckCircle2,
                      earlier: earlierMetrics.safe,
                      later: laterMetrics.safe,
                      delta: compareDeltas.safeDelta,
                      tone:
                        compareDeltas.safeDelta > 0
                          ? ("better" as TrendTone)
                          : compareDeltas.safeDelta < 0
                            ? ("worse" as TrendTone)
                            : ("neutral" as TrendTone),
                    },
                    {
                      key: "suspicious",
                      label: "Suspicious",
                      icon: AlertTriangle,
                      earlier: earlierMetrics.suspicious,
                      later: laterMetrics.suspicious,
                      delta: compareDeltas.suspiciousDelta,
                      tone: riskTone(compareDeltas.suspiciousDelta),
                    },
                    {
                      key: "high",
                      label: "High risk",
                      icon: ShieldAlert,
                      earlier: earlierMetrics.high,
                      later: laterMetrics.high,
                      delta: compareDeltas.highDelta,
                      tone: riskTone(compareDeltas.highDelta),
                    },
                  ] as const
                ).map((metric) => (
                  <div key={metric.key} className="report-compare-metric">
                    <metric.icon size={18} />
                    <span>{metric.label}</span>
                    <div className="report-compare-metric-values">
                      <strong>{metric.later}</strong>
                      <small>
                        was {metric.earlier}
                      </small>
                    </div>
                    <span
                      className={`report-compare-delta ${metric.tone}`}
                    >
                      <TrendIcon tone={metric.tone} />
                      {formatSigned(metric.delta)}
                    </span>
                  </div>
                ))}
              </div>

              {(earlierMetrics.avgWebsiteScore !== null ||
                laterMetrics.avgWebsiteScore !== null) && (
                <div className="report-compare-score">
                  <div>
                    <span>Avg website risk score</span>
                    <strong>
                      {laterMetrics.avgWebsiteScore ?? "—"}
                      <small>/100 later</small>
                    </strong>
                  </div>
                  <div>
                    <span>Earlier</span>
                    <strong>
                      {earlierMetrics.avgWebsiteScore ?? "—"}
                      <small>/100</small>
                    </strong>
                  </div>
                  <div>
                    <span>Change</span>
                    <strong
                      className={`report-compare-delta ${
                        compareDeltas.scoreDelta === null
                          ? "neutral"
                          : riskTone(compareDeltas.scoreDelta)
                      }`}
                    >
                      {compareDeltas.scoreDelta === null
                        ? "—"
                        : formatSigned(compareDeltas.scoreDelta)}
                    </strong>
                  </div>
                </div>
              )}
            </section>

            <section className="report-section">
              <div className="report-section-title">
                <h3>Categories</h3>
              </div>

              <div className="report-compare-table">
                <div className="report-compare-table-head">
                  <span>Category</span>
                  <span>{earlierLabel}</span>
                  <span>{laterLabel}</span>
                  <span>Flagged Δ</span>
                </div>
                {CATEGORIES.map(({ id, label, icon: Icon }) => {
                  const earlier = earlierMetrics.byCategory[id];
                  const later = laterMetrics.byCategory[id];
                  const flaggedDelta = deltaOf(later.flagged, earlier.flagged);
                  const tone = riskTone(flaggedDelta);

                  return (
                    <div key={id} className="report-compare-table-row">
                      <span className="report-compare-category">
                        <span className="report-category-icon">
                          <Icon size={16} />
                        </span>
                        {label}
                      </span>
                      <span>
                        {earlier.total}
                        {earlier.flagged > 0 && (
                          <small> · {earlier.flagged} flagged</small>
                        )}
                      </span>
                      <span>
                        {later.total}
                        {later.flagged > 0 && (
                          <small> · {later.flagged} flagged</small>
                        )}
                      </span>
                      <span className={`report-compare-delta ${tone}`}>
                        <TrendIcon tone={tone} />
                        {formatSigned(flaggedDelta)}
                      </span>
                    </div>
                  );
                })}
              </div>

              <p className="report-footnote">
                Lower flagged and high-risk counts mean stronger security.
                Activity volume alone is not scored as better or worse.
              </p>
            </section>
          </>
        ) : (
          <>
            <section className="report-section">
              <div className="report-section-title">
                <h3>Summary</h3>
              </div>

              <div className="report-metrics">
                <div>
                  <Activity size={18} />
                  <span>Total</span>
                  <strong>{items.length}</strong>
                </div>
                <div>
                  <CheckCircle2 size={18} />
                  <span>Safe</span>
                  <strong>{counts.safe}</strong>
                </div>
                <div>
                  <AlertTriangle size={18} />
                  <span>Suspicious</span>
                  <strong>{counts.suspicious}</strong>
                </div>
                <div>
                  <ShieldAlert size={18} />
                  <span>High risk</span>
                  <strong>{counts.high}</strong>
                </div>
              </div>
              {(counts.unverified > 0 || counts.info > 0) && (
                <p className="report-footnote">
                  Includes {counts.info > 0 ? `${counts.info} informational` : ""}
                  {counts.info > 0 && counts.unverified > 0 ? " · " : ""}
                  {counts.unverified > 0
                    ? `${counts.unverified} unverified`
                    : ""}
                  {" "}
                  (counted in Total, not in Safe/Suspicious/High)
                </p>
              )}
            </section>

            <section className="report-section">
              <div className="report-section-title">
                <h3>Categories</h3>
              </div>

              <div className="report-category-grid">
                {CATEGORIES.map(({ id, label, icon: Icon }) => {
                  const group = counts.byCategory[id];
                  const warnings = group.flagged;

                  return (
                    <button
                      type="button"
                      key={id}
                      className={`report-category-card ${
                        selectedCategory === id ? "selected" : ""
                      }`}
                      onClick={() => {
                        setSelectedCategory(
                          selectedCategory === id ? "all" : id,
                        );
                        document
                          .getElementById("report-activity")
                          ?.scrollIntoView({
                            behavior: "smooth",
                            block: "start",
                          });
                      }}
                    >
                      <span className="report-category-top">
                        <span className="report-category-icon">
                          <Icon size={16} />
                        </span>
                        <strong>{group.total}</strong>
                      </span>
                      <span className="report-category-name">{label}</span>
                      {warnings > 0 && (
                        <small className="report-category-flag">
                          {warnings} flagged
                        </small>
                      )}
                    </button>
                  );
                })}
              </div>
            </section>

            <section className="report-section" id="report-activity">
              <div className="report-section-title">
                <h3>Activity</h3>
              </div>

              <div className="report-log-controls no-print">
                <label className="report-search">
                  <Search size={16} />
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search activity…"
                  />
                  {search && (
                    <button
                      type="button"
                      aria-label="Clear search"
                      onClick={() => setSearch("")}
                    >
                      <X size={15} />
                    </button>
                  )}
                </label>

                <select
                  aria-label="Activity category"
                  value={selectedCategory}
                  onChange={(event) =>
                    setSelectedCategory(event.target.value as Category | "all")
                  }
                >
                  <option value="all">All categories</option>
                  {CATEGORIES.map((category) => (
                    <option key={category.id} value={category.id}>
                      {category.label}
                    </option>
                  ))}
                </select>
              </div>

              <div
                className={`report-log-head ${
                  selectedCategory === "news" ? "news-view" : ""
                }`}
              >
                <span>Activity</span>
                <span>Category</span>

                {selectedCategory !== "news" && <span>Finding</span>}

                <span>Time</span>
              </div>

              <div className="report-log-table">
                {shown.length ? (
                  shown.map((item) => {
                    const category = CATEGORIES.find(
                      (category) => category.id === item.category,
                    )!;

                    const open = expanded === item.id;

                    return (
                      <div key={item.id} className="report-log-entry">
                        <button
                          type="button"
                          className={`report-log-row ${
                            selectedCategory === "news" ? "news-view" : ""
                          }`}
                          onClick={() => setExpanded(open ? null : item.id)}
                          aria-expanded={open}
                        >
                          <span className="report-log-main">
                            {open ? (
                              <ChevronDown size={16} />
                            ) : (
                              <ChevronRight size={16} />
                            )}

                            <span>
                              <strong>{item.title}</strong>
                              <small>{item.detail}</small>
                            </span>
                          </span>

                          <span>{category.label}</span>
                          {selectedCategory !== "news" && (
                            <span>
                              {item.category !== "news" && (
                                <span
                                  className={`report-finding ${getResultClass(item)}`}
                                >
                                  {getResultLabel(item)}
                                </span>
                              )}
                            </span>
                          )}

                          <span className="report-log-time">
                            {dateText(item.occurredAt)}
                          </span>
                        </button>

                        {open && (
                          <div className="report-log-detail">
                            <p>
                              <strong>Source</strong>{" "}
                              {SOURCE_LABELS[item.source]}
                            </p>

                            {item.category === "passwords" && (
                              <p>
                                Password strength:{" "}
                                <span
                                  className={`report-finding ${getResultClass(item)}`}
                                >
                                  {getResultLabel(item)}
                                </span>
                                . The password itself is not stored.
                              </p>
                            )}

                            {item.category !== "passwords" &&
                              typeof item.score === "number" && (
                                <p>
                                  <strong>Risk score</strong> {item.score}/100
                                </p>
                              )}

                            {item.notes?.length ? (
                              <ul>
                                {item.notes.map((note, index) => (
                                  <li key={index}>{note}</li>
                                ))}
                              </ul>
                            ) : null}
                          </div>
                        )}
                      </div>
                    );
                  })
                ) : (
                  <div className="report-empty">
                    <FileText size={25} />

                    <strong>
                      {loading
                        ? "Loading your report…"
                        : items.length === 0
                          ? "No security activity yet"
                          : "No matching activities"}
                    </strong>

                    <p>
                      {loading
                        ? "Gathering recent activity…"
                        : items.length === 0
                          ? "Scan emails, run Device Scanner, check security items, or use Website Tracker — activity appears here automatically."
                          : "Try a different period or clear your search."}
                    </p>
                  </div>
                )}
              </div>

              <p className="report-footnote">
                {shown.length} of {items.length} · {periodLabel.toLowerCase()}
              </p>
            </section>
          </>
        )}

        {/* REPORT FOOTER */}
        <footer className="report-footer">
          <span className="report-footer-brand">
            <img
              src="/logo.png"
              alt="CyberGuard logo"
              className="report-footer-logo"
            />
            CYBERGUARD
          </span>

          <span className="report-footer-date">
            {new Date().toLocaleDateString("en-US", {
              month: "long",
              day: "numeric",
              year: "numeric",
            })}
          </span>
        </footer>
      </article>
    </main>
  );
}
