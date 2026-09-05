// Real backend API service — same function signatures as mockApi.js, so every
// component that used mock data works unchanged after switching the import.
//
// Base URL is configurable via VITE_API_BASE_URL (see .env.example) so this
// works against localhost during development and a deployed backend later
// without code changes.

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

async function fetchJson(path) {
  const res = await fetch(`${BASE_URL}${path}`);
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API error ${res.status} on ${path}: ${body || res.statusText}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Milestone 1 API Functions
// ---------------------------------------------------------------------------

export async function getEvents(filters = {}) {
  const params = new URLSearchParams();
  if (filters.severity && filters.severity !== "All") params.set("severity", filters.severity);
  if (filters.eventType && filters.eventType !== "All") params.set("event_type", filters.eventType);
  const query = params.toString() ? `?${params.toString()}` : "";
  return fetchJson(`/events${query}`);
}

export async function getStats() {
  return fetchJson("/stats");
}

export async function getThreats() {
  return fetchJson("/threats");
}

export async function getThreatIntel(filters = {}) {
  const params = new URLSearchParams();
  if (filters.severity && filters.severity !== "All") params.set("severity", filters.severity);
  const query = params.toString() ? `?${params.toString()}` : "";
  return fetchJson(`/threat-intel${query}`);
}

export async function getVulnerabilities(filters = {}) {
  const params = new URLSearchParams();
  if (filters.severity && filters.severity !== "All") params.set("severity", filters.severity);
  const query = params.toString() ? `?${params.toString()}` : "";
  return fetchJson(`/vulnerabilities${query}`);
}

export async function createEvent(eventData) {
  const res = await fetch(`${BASE_URL}/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(eventData),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API error ${res.status} on POST /events: ${body || res.statusText}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Milestone 2 AI Threat Detection API Functions
// ---------------------------------------------------------------------------

export async function getPredictions(filters = {}) {
  const params = new URLSearchParams();
  if (filters.verdict && filters.verdict !== "All") params.set("verdict", filters.verdict);
  if (filters.threat_type && filters.threat_type !== "All") params.set("threat_type", filters.threat_type);
  if (filters.severity && filters.severity !== "All") params.set("severity", filters.severity);
  if (filters.event_id) params.set("event_id", filters.event_id);
  else if (filters.search) params.set("event_id", filters.search);
  if (filters.limit) params.set("limit", filters.limit);
  if (filters.skip !== undefined && filters.skip !== null) params.set("skip", filters.skip);
  const query = params.toString() ? `?${params.toString()}` : "";
  return fetchJson(`/predictions${query}`);
}

export async function getPredictionById(predictionId) {
  if (!predictionId) throw new Error("predictionId is required");
  return fetchJson(`/predictions/${encodeURIComponent(predictionId)}`);
}

export async function getAnomalies(filters = {}) {
  const params = new URLSearchParams();
  if (filters.limit) params.set("limit", filters.limit);
  if (filters.skip !== undefined && filters.skip !== null) params.set("skip", filters.skip);
  const query = params.toString() ? `?${params.toString()}` : "";
  return fetchJson(`/anomalies${query}`);
}

export async function getThreatSummary() {
  return fetchJson("/threat-summary");
}

export async function getModelPerformance() {
  return fetchJson("/model-performance");
}

export async function getPredictionTrend() {
  return fetchJson("/prediction-trend");
}

export async function getTopPredictions(limit = 3) {
  const params = new URLSearchParams();
  if (limit) params.set("limit", limit);
  const query = params.toString() ? `?${params.toString()}` : "";
  return fetchJson(`/top-predictions${query}`);
}

export async function predictEvent(eventData) {
  const res = await fetch(`${BASE_URL}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(eventData),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API error ${res.status} on POST /predict: ${body || res.statusText}`);
  }
  return res.json();
}

// Pure, synchronous — computes the AI insight summary from events already in hand
export function computeAiInsights(events) {
  const topRiskEvents = [...events].sort((a, b) => b.riskScore - a.riskScore).slice(0, 3);

  const techniqueCounts = {};
  events.forEach((e) => {
    const key = e.mitre?.id || "N/A";
    techniqueCounts[key] = techniqueCounts[key] || { ...(e.mitre || { id: "N/A", technique: "Unknown", tactic: "Unknown" }), count: 0 };
    techniqueCounts[key].count += 1;
  });
  const topTechniques = Object.values(techniqueCounts).sort((a, b) => b.count - a.count).slice(0, 3);

  return {
    topRiskEvents,
    topTechniques,
    summary: `${topRiskEvents.length} high-risk events detected in the last session, most frequently linked to ${topTechniques[0]?.technique || "unknown techniques"}.`,
  };
}

// Convenience wrapper for callers that don't already have events in hand.
export async function getAiInsights() {
  const events = await getEvents();
  return computeAiInsights(events);
}

export const EVENT_TYPE_OPTIONS = [
  "Brute Force", "Failed Login", "Login Success", "File Access", "Port Scan",
  "Malware Detection", "USB Device Connected", "Privilege Escalation",
  "SQL Injection Attempt", "Phishing Email",
];
export const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low"];
export const STATUS_OPTIONS = ["Open", "Investigating", "Resolved", "Closed"];
export const VERDICT_OPTIONS = ["Normal", "Suspicious", "Critical"];
