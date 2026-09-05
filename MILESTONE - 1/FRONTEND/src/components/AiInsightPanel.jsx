import { BrainCircuit, Target } from "lucide-react";

const SEVERITY_DOT = {
  Critical: "bg-red-500",
  High: "bg-orange-500",
  Medium: "bg-yellow-500",
  Low: "bg-emerald-500",
};

export default function AiInsightPanel({ insights, avgRiskScore }) {
  if (!insights) return null;

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 shadow-sm text-slate-100 hover:border-slate-700 hover:-translate-y-0.5 transition-all duration-200">
      <div className="flex items-center justify-between mb-3 border-b border-[#1F2937] pb-3">
        <div className="flex items-center gap-2">
          <BrainCircuit className="w-5 h-5 text-blue-400" />
          <h3 className="text-sm font-bold text-slate-100">AI Threat Intelligence Summary</h3>
        </div>
        {typeof avgRiskScore === "number" && (
          <div className="text-right flex items-center gap-2">
            <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">Avg Risk Score:</span>
            <span className="text-xl font-extrabold text-blue-400 font-mono">{avgRiskScore}%</span>
          </div>
        )}
      </div>

      <p className="text-xs md:text-sm text-slate-300 leading-relaxed mb-4">{insights.summary}</p>

      <div className="grid gap-4 sm:grid-cols-2">
        {/* Top risk events */}
        <div>
          <p className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">
            Highest Risk Events
          </p>
          <div className="space-y-1.5">
            {insights.topRiskEvents.map((e) => (
              <div key={e.id} className="flex items-center justify-between bg-[#0B1329] border border-[#1F2937] rounded-lg px-3 py-1.5">
                <div className="flex items-center gap-2 min-w-0">
                  <span className={`w-2 h-2 rounded-full shrink-0 ${SEVERITY_DOT[e.severity]}`}></span>
                  <span className="text-xs text-slate-300 truncate font-medium">{e.eventType}</span>
                </div>
                <span className="text-xs font-mono font-bold text-blue-400 shrink-0 ml-2">
                  {e.riskScore}%
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Top MITRE techniques */}
        <div>
          <p className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">
            Most Frequent Techniques
          </p>
          <div className="space-y-1.5">
            {insights.topTechniques.map((t) => (
              <div key={t.id} className="flex items-center justify-between bg-[#0B1329] border border-[#1F2937] rounded-lg px-3 py-1.5">
                <div className="flex items-center gap-2 min-w-0">
                  <Target className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                  <span className="text-xs text-slate-300 truncate font-medium" title={t.technique}>{t.technique}</span>
                </div>
                <span className="text-xs font-mono font-bold text-slate-400 shrink-0 ml-2">
                  {t.id} · {t.count}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
