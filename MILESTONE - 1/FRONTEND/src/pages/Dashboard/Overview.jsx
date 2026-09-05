import { useState } from "react";
import KpiCard from "../../components/KpiCard";
import Filters from "../../components/Filters";
import EventTable from "../../components/EventTable";
import AiInsightPanel from "../../components/AiInsightPanel";
import ThreatDistributionChart from "../../charts/ThreatDistributionChart";
import TopAttackTypesChart from "../../charts/TopAttackTypesChart";
import EventTrendChart from "../../charts/EventTrendChart";
import { getEvents, getStats, getThreats, computeAiInsights } from "../../services/api";
import { useAsyncData } from "../../hooks/useAsyncData";
import ErrorBanner from "../../components/ErrorBanner";

export default function Overview() {
  const [filters, setFilters] = useState({ severity: "All", eventType: "All", date: "", ip: "" });

  const { data, loading, error } = useAsyncData(async () => {
    const [eventsData, statsData, threatsData] = await Promise.all([
      getEvents(),
      getStats(),
      getThreats(),
    ]);
    return { events: eventsData, stats: statsData, threats: threatsData };
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

  const { events, stats, threats } = data;
  const insights = computeAiInsights(events);

  return (
    <div className="grid gap-5 md:gap-6">
      {/* 5 KPI Summary Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 md:gap-4">
        <KpiCard title="Total Events" value={stats.total_events.toLocaleString()} statusText="Normal" statusType="normal" iconType="activity" />
        <KpiCard title="Critical Threats" value={stats.critical_events} statusText="Elevated" statusType="critical" iconType="critical" />
        <KpiCard title="High Severity Alerts" value={stats.high_events} statusText="Moderate" statusType="moderate" iconType="lightning" />
        <KpiCard title="Vulnerabilities" value={stats.vulnerabilities} statusText="Moderate" statusType="moderate" iconType="lock" />
        <KpiCard title="Active Incidents" value={stats.active_incidents} statusText="Critical" statusType="critical" iconType="alert" />
      </section>

      {/* AI Threat Insight Panel */}
      <AiInsightPanel insights={insights} avgRiskScore={stats.avg_risk_score} />

      {/* Distribution + Top Attack Types Charts (Increased Focus) */}
      <div className="grid gap-5 lg:grid-cols-2">
        <ThreatDistributionChart events={events} />
        <TopAttackTypesChart threats={threats} />
      </div>

      {/* Threat Trend (Last 24 Hours) Chart */}
      <EventTrendChart events={events} />

      {/* Search & Filters + Security Events Table */}
      <Filters filters={filters} setFilters={setFilters} />
      <EventTable events={events} filters={filters} />
    </div>
  );
}
