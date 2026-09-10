import React from "react";
import {
  FiGitCommit,
  FiTrendingUp,
  FiArrowRight,
  FiInfo,
  FiLayers,
  FiClock,
  FiKey,
} from "react-icons/fi";
import { RiskScoreBadge, RiskLevelBadge } from "./RiskBadge";

export default function RiskScoreComparisonCard({ comparison, incident }) {
  if (!comparison && !incident) return null;

  const beforeScore =
    comparison?.before_correlation !== undefined
      ? comparison.before_correlation
      : incident?.risk_score ?? 0;
  const afterScore =
    comparison?.after_correlation !== undefined
      ? comparison.after_correlation
      : incident?.risk_score ?? 0;
  const change = comparison?.change ?? 0;
  const relatedCount =
    comparison?.related_events_count ?? incident?.related_events_count ?? 0;
  const chainDetected =
    comparison?.attack_chain_detected ?? incident?.attack_chain_detected ?? false;
  const chainType =
    comparison?.attack_chain_type ?? incident?.attack_chain_type ?? null;
  const timeWindow = comparison?.time_window_minutes ?? 15;
  const correlationKeys =
    comparison?.correlation_keys && comparison.correlation_keys.length > 0
      ? comparison.correlation_keys
      : ["username", "source_ip", "asset_name"];

  const changeReason =
    comparison?.change_reason ||
    "Correlation increased investigation context but did not alter the base risk score.";

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 md:p-6 space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1F2937] pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-blue-500/15 text-blue-400 border border-blue-500/30">
            <FiTrendingUp className="text-base" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100">
              Risk Score Comparison — Before vs After Correlation
            </h3>
            <p className="text-xs text-slate-400">
              Deterministic 5-factor evaluation compared with contextual correlation signals
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1.5 self-start sm:self-auto">
          <span className="text-[11px] font-semibold text-slate-400">Delta:</span>
          <span
            className={`font-mono text-xs font-bold px-2 py-0.5 rounded border ${
              change > 0
                ? "bg-amber-500/20 text-amber-300 border-amber-500/30"
                : change < 0
                ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
                : "bg-slate-800 text-slate-300 border-slate-700"
            }`}
          >
            {change >= 0 ? `+${change}` : change} pts
          </span>
        </div>
      </div>

      {/* Before vs After Cards */}
      <div className="grid grid-cols-1 md:grid-cols-11 gap-3 items-center">
        {/* Before Correlation */}
        <div className="md:col-span-5 bg-[#1E293B]/70 border border-[#1F2937] rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
              Before Correlation
            </span>
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              Anchor Event Base
            </span>
          </div>
          <div className="flex items-center gap-3 pt-1">
            <div className="text-2xl font-black font-mono text-blue-400">{beforeScore}</div>
            <div className="text-xs text-slate-300">
              <span className="font-semibold text-slate-100 block">Single-Event Telemetry</span>
              <span className="text-[11px] text-slate-400">
                5-factor weighted baseline: Threat Severity, ML Confidence, Asset, CVSS, Threat Intel
              </span>
            </div>
          </div>
        </div>

        {/* Transition Indicator */}
        <div className="md:col-span-1 flex items-center justify-center text-slate-500 py-1 md:py-0">
          <div className="p-2 rounded-full bg-[#1E293B] border border-[#1F2937]">
            <FiArrowRight className="text-sm text-blue-400" />
          </div>
        </div>

        {/* After Correlation */}
        <div className="md:col-span-5 bg-[#1E293B]/70 border border-[#1F2937] rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold uppercase tracking-wider text-purple-400">
              After Correlation
            </span>
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
              Full Contextual Evaluation
            </span>
          </div>
          <div className="flex items-center gap-3 pt-1">
            <div className="text-2xl font-black font-mono text-purple-300">{afterScore}</div>
            <div className="text-xs text-slate-300">
              <span className="font-semibold text-slate-100 block">Contextual Risk State</span>
              <span className="text-[11px] text-slate-400">
                {chainDetected
                  ? `Correlated with ${relatedCount} events into a validated ${chainType}`
                  : relatedCount > 0
                  ? `Correlated with ${relatedCount} related events in sliding window`
                  : "Isolated single event — no multi-stage threat detected"}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Explanation Box */}
      <div className="p-3.5 rounded-xl bg-slate-900/60 border border-[#1F2937] space-y-2">
        <div className="flex items-start gap-2.5 text-xs text-slate-300">
          <FiInfo className="text-blue-400 text-sm mt-0.5 shrink-0" />
          <div>
            <span className="font-semibold text-slate-200">Impact Analysis: </span>
            <span>{changeReason}</span>
          </div>
        </div>

        {/* Correlation Context Pills */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 border-t border-[#1F2937]/70 text-[11px]">
          <div className="flex items-center gap-1.5 text-slate-400">
            <FiLayers className="text-slate-500" />
            <span>Correlated Events:</span>
            <strong className="text-slate-200 font-mono">{relatedCount}</strong>
          </div>
          <div className="flex items-center gap-1.5 text-slate-400">
            <FiClock className="text-slate-500" />
            <span>Sliding Window:</span>
            <strong className="text-slate-200 font-mono">{timeWindow}m</strong>
          </div>
          <div className="flex items-center gap-1.5 text-slate-400">
            <FiGitCommit className="text-slate-500" />
            <span>Attack Chain:</span>
            <strong className="text-slate-200 truncate">{chainDetected ? chainType : "None"}</strong>
          </div>
          <div className="flex items-center gap-1.5 text-slate-400">
            <FiKey className="text-slate-500" />
            <span>Pivots:</span>
            <strong className="text-slate-200 truncate">{correlationKeys.join(", ")}</strong>
          </div>
        </div>
      </div>
    </div>
  );
}
