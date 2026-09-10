import { useState } from "react";
import { Link } from "react-router-dom";
import { FiShield, FiArrowRight } from "react-icons/fi";
import KpiCard from "../../components/KpiCard";
import Filters from "../../components/Filters";
import EventTable from "../../components/EventTable";
import AiInsightPanel from "../../components/AiInsightPanel";
import ThreatDistributionChart from "../../charts/ThreatDistributionChart";
import TopAttackTypesChart from "../../charts/TopAttackTypesChart";
import EventTrendChart from "../../charts/EventTrendChart";
import {
  getEvents,
  getStats,
  getThreats,
  computeAiInsights,
  getThreatSummary,
  getModelPerformance,
  getTopPredictions,
} from "../../services/api";
import { useAsyncData } from "../../hooks/useAsyncData";
import ErrorBanner from "../../components/ErrorBanner";

export default function Overview() {
  const [filters, setFilters] = useState({ severity: "All", eventType: "All", date: "", ip: "" });

  const { data, loading, error } = useAsyncData(async () => {
    const [eventsData, statsData, threatsData, summaryData, perfData, topPreds] = await Promise.all([
      getEvents(),
      getStats(),
      getThreats(),
      getThreatSummary().catch(() => []),
      getModelPerformance().catch(() => null),
      getTopPredictions(3).catch(() => []),
    ]);
    return {
      events: eventsData,
      stats: statsData,
      threats: threatsData,
      m2Summary: summaryData,
      m2Perf: perfData,
      topPredictions: topPreds,
    };
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="flex items-center gap-3 text-slate-400 text-sm">
          <span className="h-2 w-2 rounded-full bg-blue-500 animate-ping"></span>
          <span>Loading dashboard security analytics...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return <ErrorBanner message={error} />;
  }

  const { events, stats, threats, m2Summary, m2Perf, topPredictions } = data;
  const insights = computeAiInsights(events);

  return (
    <div className="grid gap-5 md:gap-6">
      {/* M3 Risk Prioritization Quick Bar */}
      <div className="bg-gradient-to-r from-blue-900/40 via-purple-900/30 to-[#111827] border border-blue-500/30 rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-600/30 text-blue-400 border border-blue-500/40 shrink-0">
            <FiShield className="text-xl" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-100">Milestone 3 Risk Prioritization Active</h3>
              <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 text-[10px] font-bold font-mono">
                M3 ENGINE
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-0.5">
              5-factor deterministic risk scoring, context enrichment, and canonical attack chain reconstruction.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Link
            to="/dashboard/risk-overview"
            className="px-3 py-1.5 rounded-lg bg-[#1E293B] hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-[#1F2937] transition-colors"
          >
            Risk Overview
          </Link>
          <Link
            to="/dashboard/incidents"
            className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white shadow transition-colors flex items-center gap-1"
          >
            <span>Priority Incidents</span>
            <FiArrowRight />
          </Link>
        </div>
      </div>
      {/* 5 KPI Summary Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 md:gap-4">
        <KpiCard title="Total Events" value={stats.total_events.toLocaleString()} statusText="M1 Telemetry" statusType="normal" iconType="activity" />
        <KpiCard title="Critical Events (Raw)" value={stats.critical_events.toLocaleString()} statusText="M1 Severity 4" statusType="critical" iconType="critical" />
        <KpiCard title="High Severity Alerts" value={stats.high_events.toLocaleString()} statusText="M1 Telemetry" statusType="moderate" iconType="lightning" />
        <KpiCard title="Vulnerabilities" value={stats.vulnerabilities.toLocaleString()} statusText="CVE Records" statusType="normal" iconType="lock" />
        <KpiCard title="Active Incidents" value={stats.active_incidents.toLocaleString()} statusText="Operational" statusType="critical" iconType="alert" />
      </section>

      {/* AI Threat Insight Panel */}
      <AiInsightPanel
        insights={insights}
        avgRiskScore={stats.avg_risk_score}
        m2Summary={m2Summary}
        m2Perf={m2Perf}
        topPredictions={topPredictions}
      />

      {/* Distribution + Top Attack Types Charts */}
      <div className="grid gap-5 lg:grid-cols-2">
        <ThreatDistributionChart events={events} />
        <TopAttackTypesChart threats={threats} />
      </div>

      {/* Threat Trend Chart */}
      <EventTrendChart events={events} />

      {/* Search & Filters + Security Events Table */}
      <Filters filters={filters} setFilters={setFilters} />
      <EventTable events={events} filters={filters} />
    </div>
  );
}
