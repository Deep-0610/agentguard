"use client";

import { useCallback, useEffect, useState } from "react";

async function api(path) {
  const response = await fetch("/api/control-plane/" + path, { cache: "no-store" });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || "Request failed (" + response.status + ")");
  return body;
}

function Metric({ label, value, detail }) {
  return <article className="metric"><span>{label}</span><strong>{value ?? "—"}</strong><small>{detail}</small></article>;
}

export default function Home() {
  const [key, setKey] = useState("");
  const [authenticated, setAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [summary, setSummary] = useState(null);
  const [identities, setIdentities] = useState([]);
  const [findings, setFindings] = useState([]);
  const [audit, setAudit] = useState([]);

  const load = useCallback(async () => {
    setError("");
    try {
      const [s, i, f, a] = await Promise.all([
        api("v1/dashboard/summary"),
        api("v1/identities?limit=10"),
        api("v1/findings?limit=10"),
        api("v1/audit-events?limit=8")
      ]);
      setSummary(s);
      setIdentities(i.items || []);
      setFindings(f.items || []);
      setAudit(a.items || []);
      setAuthenticated(true);
    } catch (e) {
      setError(e.message);
      if (e.message.includes("Authentication required") || e.message.includes("Invalid or expired")) setAuthenticated(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    fetch("/api/session", { cache: "no-store" }).then(r => r.json()).then(s => {
      if (!active) return;
      if (s.authenticated) return load();
      setAuthenticated(false);
    }).catch(() => setError("Unable to initialize dashboard session.")).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [load]);

  async function signIn(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/session", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ apiKey: key }) });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || "Sign-in failed.");
      setKey("");
      await load();
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function signOut() {
    await fetch("/api/session", { method: "DELETE" });
    setAuthenticated(false);
    setSummary(null);
    setIdentities([]);
    setFindings([]);
    setAudit([]);
  }

  if (loading) return <main className="center"><p>Loading AgentGuard…</p></main>;

  if (!authenticated) return (
    <main className="auth-shell">
      <section className="auth-card">
        <div className="brand-mark">AG</div>
        <p className="eyebrow">SECURITY CONTROL PLANE</p>
        <h1>AgentGuard</h1>
        <p className="muted">Sign in with a tenant API key. Your key is encrypted in an HTTP-only server session and is never stored in browser local storage.</p>
        <form onSubmit={signIn}>
          <label htmlFor="api-key">AgentGuard API key</label>
          <input id="api-key" type="password" autoComplete="off" value={key} onChange={e => setKey(e.target.value)} placeholder="ag_live_…" required />
          <button disabled={busy || !key.trim()}>{busy ? "Connecting…" : "Connect securely"}</button>
        </form>
        {error && <p className="error" role="alert">{error}</p>}
        <p className="footnote">Early-access dashboard. API-key access is not a substitute for OIDC SSO or user-level MFA.</p>
      </section>
    </main>
  );

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand"><span className="brand-mark small">AG</span><div><strong>AgentGuard</strong><small>CONTROL PLANE</small></div></div>
        <div className="actions"><button className="secondary" onClick={load}>Refresh</button><button className="secondary" onClick={signOut}>Sign out</button></div>
      </header>
      <section className="intro"><div><p className="eyebrow">OVERVIEW</p><h1>Security posture</h1><p className="muted">Inventory and risk signals across your non-human identities.</p></div><span className="live">Connected</span></section>
      {error && <p className="error banner" role="alert">{error}</p>}
      <section className="metrics">
        <Metric label="Identities" value={summary?.identities} detail="Discovered assets" />
        <Metric label="Open findings" value={summary?.open_findings} detail="Require review" />
        <Metric label="Critical findings" value={summary?.critical_findings} detail="Highest severity" />
        <Metric label="Orphaned identities" value={summary?.orphaned_identities} detail="No active owner" />
      </section>
      <section className="panels">
        <article className="panel wide"><div className="panel-heading"><div><h2>Identity inventory</h2><p>Recently observed non-human identities</p></div><span>{identities.length} shown</span></div>
          <div className="table-wrap"><table><thead><tr><th>Identity</th><th>Type</th><th>Source</th><th>Risk</th><th>Owner</th></tr></thead><tbody>
            {identities.map((item, index) => <tr key={item.id || index}><td><strong>{item.name || item.external_id || "Unnamed"}</strong><small>{item.external_key || item.id}</small></td><td>{item.kind || "—"}</td><td>{item.source || "—"}</td><td><span className={"risk " + ((item.risk_score || 0) >= 80 ? "high" : (item.risk_score || 0) >= 50 ? "medium" : "low")}>{item.risk_score ?? 0}</span></td><td>{item.owner_status || "Unknown"}</td></tr>)}
            {!identities.length && <tr><td colSpan="5" className="empty">No identities ingested yet.</td></tr>}
          </tbody></table></div>
        </article>
        <article className="panel"><div className="panel-heading"><div><h2>Findings</h2><p>Latest risk observations</p></div></div>
          <div className="stack">{findings.map((item, index) => <div className="list-item" key={item.id || index}><span className={"severity " + (item.severity || "info")}></span><div><strong>{item.title}</strong><small>{item.rule_id} · {item.status}</small></div><b>{item.severity}</b></div>)}{!findings.length && <p className="empty">No findings to display.</p>}</div>
        </article>
        <article className="panel"><div className="panel-heading"><div><h2>Audit activity</h2><p>Recent control-plane events</p></div></div>
          <div className="stack">{audit.map((item, index) => <div className="list-item" key={item.id || index}><span className="audit-dot"></span><div><strong>{item.event_type}</strong><small>{item.actor} · {item.created_at ? new Date(item.created_at).toLocaleString() : "Time unavailable"}</small></div></div>)}{!audit.length && <p className="empty">No audit events yet.</p>}</div>
        </article>
      </section>
      <footer>AgentGuard early access · Findings are heuristic signals, not a security certification.</footer>
    </main>
  );
}
