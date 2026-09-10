import React from "react";

export const RISK_LEVEL_STYLES = {
  Critical: "bg-red-500/20 text-red-300 border-red-500/40",
  High: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  Moderate: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  Medium: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  Low: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
};

export const PRIORITY_STYLES = {
  CRITICAL_IMMEDIATE: "bg-red-600/25 text-red-200 border-red-500/50 font-bold",
  HIGH_IMMEDIATE: "bg-orange-600/25 text-orange-200 border-orange-500/50 font-bold",
  HIGH: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  MEDIUM: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  LOW: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
};

export const STATUS_STYLES = {
  Open: "bg-red-500/15 text-red-300 border-red-500/30",
  Investigating: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  Resolved: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  "False Positive": "bg-slate-500/15 text-slate-300 border-slate-500/30",
};

export function RiskLevelBadge({ level, size = "sm" }) {
  const style = RISK_LEVEL_STYLES[level] || "bg-slate-500/20 text-slate-300 border-slate-500/30";
  const sizeClass = size === "lg" ? "px-3 py-1 text-xs" : "px-2 py-0.5 text-[11px]";
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border font-semibold tracking-wide ${style} ${sizeClass}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current opacity-80" />
      <span>{level || "Unknown"}</span>
    </span>
  );
}

export function PriorityBadge({ priority, size = "sm" }) {
  const style = PRIORITY_STYLES[priority] || "bg-slate-500/20 text-slate-300 border-slate-500/30";
  const sizeClass = size === "lg" ? "px-3 py-1 text-xs" : "px-2 py-0.5 text-[11px]";
  const formatted = priority ? priority.replace("_", " ") : "UNKNOWN";
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border font-mono font-semibold tracking-wider ${style} ${sizeClass}`}>
      {formatted}
    </span>
  );
}

export function StatusBadge({ status, size = "sm" }) {
  const style = STATUS_STYLES[status] || "bg-slate-500/20 text-slate-300 border-slate-500/30";
  const sizeClass = size === "lg" ? "px-3 py-1 text-xs" : "px-2 py-0.5 text-[11px]";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border font-medium ${style} ${sizeClass}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current opacity-80" />
      <span>{status || "Open"}</span>
    </span>
  );
}

export function RiskScoreBadge({ score, level, size = "md" }) {
  const style = RISK_LEVEL_STYLES[level] || "bg-slate-500/20 text-slate-300 border-slate-500/30";
  const isLarge = size === "lg";
  return (
    <div className={`inline-flex items-center justify-center font-bold font-mono rounded-lg border ${style} ${isLarge ? "h-12 w-14 text-xl" : "h-7 w-9 text-xs"}`}>
      {score ?? "--"}
    </div>
  );
}
