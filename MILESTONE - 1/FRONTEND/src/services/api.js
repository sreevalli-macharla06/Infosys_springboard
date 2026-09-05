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

// Pure, synchronous — computes the AI insight summary from events already in hand
// (avoids a second network round-trip when the caller already fetched events).
export function computeAiInsights(events) {
  const topRiskEvents = [...events].sort((a, b) => b.riskScore - a.riskScore).slice(0, 3);

  const techniqueCounts = {};
  events.forEach((e) => {
    const key = e.mitre.id;
    techniqueCounts[key] = techniqueCounts[key] || { ...e.mitre, count: 0 };
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

// Filter/severity/event-type option lists still come from the frontend's own
// constants — the backend doesn't need a dedicated endpoint just for these.
export const EVENT_TYPE_OPTIONS = [
  "Brute Force", "Failed Login", "Login Success", "File Access", "Port Scan",
  "Malware Detection", "USB Device Connected", "Privilege Escalation",
  "SQL Injection Attempt", "Phishing Email",
];
export const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low"];
export const STATUS_OPTIONS = ["Open", "Investigating", "Resolved", "Closed"];
