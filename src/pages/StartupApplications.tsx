import { useCallback, useEffect, useState } from "react";
import { Power, RefreshCw, Search, Lock, Info } from "lucide-react";
import "./StartupApplications.css";

const API_URL = "http://127.0.0.1:8765";

type StartupApplication = {
  id: string;
  name: string;
  original_name: string;
  command: string;
  executable: string | null;
  source: string;
  scope: string;
  category: string;
  enabled: boolean | null;
  manageable: boolean;
  publisher?: string;
  installed_name?: string;
};

type StartupResponse = {
  supported: boolean;
  applications: StartupApplication[];
  summary: {
    total: number;
    enabled: number;
    disabled: number;
    unknown: number;
  };
};

type StartupFilter = "all" | "enabled" | "disabled";

export default function StartupApplications() {
  const [data, setData] = useState<StartupResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<StartupFilter>("all");
  const [updating, setUpdating] = useState<string | null>(null);

  const loadApplications = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(
        `${API_URL}/system/startup-applications`
      );

      if (!response.ok) {
        throw new Error("Unable to retrieve startup applications.");
      }

      const result: StartupResponse = await response.json();

      setData(result);
    } catch {
      setError("Unable to connect to the startup application scanner.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadApplications();
  }, [loadApplications]);

  const updateStartupState = async (
    application: StartupApplication
  ) => {
    if (
      !application.manageable ||
      application.enabled === null ||
      updating !== null ||
      loading ||
      error
    ) {
      return;
    }

    const enabled = !application.enabled;

    setUpdating(application.id);
    setError("");
    setMessage("");

    try {
      const response = await fetch(
        `${API_URL}/system/startup-applications/state`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            application_id: application.id,
            enabled,
          }),
        }
      );

      const result = await response.json();

      if (!response.ok || !result.success) {
        throw new Error(
          typeof result.detail === "string"
            ? result.detail
            : "Unable to update startup application."
        );
      }

      setData((previous) => {
        if (!previous) return previous;

        const applications = previous.applications.map((item) =>
            item.id === application.id
            ? { ...item, ...result.application }
            : item
        );

        return {
            ...previous,
            applications,
            summary: {
            total: applications.length,
            enabled: applications.filter((item) => item.enabled === true).length,
            disabled: applications.filter((item) => item.enabled === false).length,
            unknown: applications.filter((item) => item.enabled === null).length,
            },
        };
        });

        setMessage(
            `${application.name} startup ${enabled ? "enabled" : "disabled"}.`
        );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to update startup application."
      );
    } finally {
      setUpdating(null);
    }
  };

  const applications = data?.applications ?? [];

  const filteredApplications = applications.filter((application) => {
  const query = search.trim().toLowerCase();

  const matchesSearch =
    application.name.toLowerCase().includes(query) ||
    application.original_name.toLowerCase().includes(query) ||
    (application.installed_name ?? "").toLowerCase().includes(query) ||
    (application.publisher ?? "").toLowerCase().includes(query);

  const matchesFilter =
    filter === "all" ||
    (filter === "enabled" && application.enabled === true) ||
    (filter === "disabled" && application.enabled === false);

  return matchesSearch && matchesFilter;
});

  const summaryCards = [
  {
    label: "Applications",
    value: data?.summary.total,
    color: "total",
  },
  {
    label: "Enabled",
    value: data?.summary.enabled,
    color: "enabled",
  },
  {
    label: "Disabled",
    value: data?.summary.disabled,
    color: "disabled",
  },
];

  return (
    <section className="guardian-section-card startup-section">
      <div className="guardian-section-header">
        <div className="startup-heading">
          <div className="startup-heading-icon">
            <Power size={22} />
          </div>

          <div>
            <h2>Startup Applications</h2>
            <p>
              Monitor and manage applications configured to launch
              when you sign in to Windows.
            </p>
          </div>
        </div>

        <button
          type="button"
          className="startup-refresh-button"
          disabled={loading || updating !== null}
          onClick={() => {
            setMessage("");
            void loadApplications();
          }}
        >
          <RefreshCw
            size={16}
            className={loading ? "startup-spinning" : ""}
          />
          Refresh
        </button>
      </div>

      {error && (
        <div className="startup-error" role="alert">
          {error}
        </div>
      )}

      {message && (
        <div className="startup-success" role="status">
          {message}
        </div>
      )}

      {data?.supported === false ? (
        <div className="startup-empty">
          Startup application management is not currently supported
          on this operating system.
        </div>
      ) : (
        <>
          <div className="startup-summary-grid">
            {summaryCards.map((card) => (
              <div
                key={card.label}
                className={`startup-summary-card ${card.color}`}
              >
                <span>{card.label}</span>
                <strong>{card.value ?? "—"}</strong>
              </div>
            ))}
          </div>

          <div className="startup-toolbar">
            <div className="startup-search">
              <Search size={17} />

              <input
                type="search"
                placeholder="Search startup applications..."
                aria-label="Search startup applications"
                value={search}
                onChange={(event) =>
                  setSearch(event.target.value)
                }
              />
            </div>

            <select
              className="startup-filter"
              aria-label="Filter startup applications"
              value={filter}
              onChange={(event) =>
                setFilter(event.target.value as StartupFilter)
              }
            >
              <option value="all">All Applications</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
          </div>

          {loading && !data ? (
            <div className="startup-empty">
              Detecting startup applications...
            </div>
          ) : !data ? (
            <div className="startup-empty">
              Startup information is unavailable.
            </div>
          ) : (
            <div className="startup-table-wrapper">
              <table className="startup-table">
                <thead>
                  <tr>
                    <th>Application</th>
                    <th>Status</th>
                    <th>Startup Control</th>
                  </tr>
                </thead>

                <tbody>
                  {filteredApplications.map((application) => {
                    const status =
                      application.enabled === null
                        ? "unknown"
                        : application.enabled
                        ? "enabled"
                        : "disabled";

                    return (
                      <tr key={application.id}>
                        <td>
                            <div className="startup-app-name">
                                <strong>
                                {application.installed_name || application.name}
                                </strong>
                                <span>
                                {application.publisher || "Unknown publisher"}
                                </span>
                            </div>
                            </td>

                        <td>
                          <span
                            className={`startup-status ${status}`}
                          >
                            <span className="startup-status-dot" />
                            {status}
                          </span>
                        </td>

                        <td>
                          {application.manageable &&
                          application.enabled !== null ? (
                            <button
                              type="button"
                              role="switch"
                              aria-checked={application.enabled}
                              aria-label={`Startup for ${application.name}`}
                              title={
                                application.enabled
                                  ? "Disable at startup"
                                  : "Enable at startup"
                              }
                              className={`startup-switch ${
                                application.enabled ? "active" : ""
                              }`}
                              disabled={
                                updating !== null ||
                                loading ||
                                Boolean(error)
                              }
                              onClick={() =>
                                void updateStartupState(application)
                              }
                            >
                              <span />
                            </button>
                          ) : (
                            <div
                              className="startup-protected"
                              title="This application is not eligible for direct startup management."
                            >
                              <Lock size={14} />
                              Read-only
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>

              {filteredApplications.length === 0 && (
                <div className="startup-empty startup-empty-state">
                    <div className="startup-empty-icon">
                    <Power size={26} />
                    </div>

                    <strong>
                    {applications.length === 0
                        ? "No supported startup applications detected"
                        : "No matching applications"}
                    </strong>

                    <p>
                    {applications.length === 0
                        ? "Supported desktop applications will appear here when they are configured to launch at Windows sign-in."
                        : "Try adjusting your search or status filter."}
                    </p>
                </div>
                )}
            </div>
          )}
        </>
      )}
    </section>
  );
}