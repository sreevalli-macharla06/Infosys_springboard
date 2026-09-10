import ErrorBanner from "../../components/ErrorBanner";
import { useAsyncData } from "../../hooks/useAsyncData";
import { getThreatIntel } from "../../services/api";

const SEVERITY_STYLE = {
  Critical: "bg-red-500/20 text-red-400 border-red-500/30",
  High: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  Medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  Low: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
};

export default function ThreatIntel() {
  const { data: iocs, loading, error } = useAsyncData(() => getThreatIntel(), []);

  return (
    <div className="grid gap-5">
      <h2 className="text-xl md:text-2xl font-extrabold text-slate-100 tracking-tight">Threat Intelligence</h2>
      {loading && (
        <div className="flex items-center justify-center min-h-[300px]">
          <div className="flex items-center gap-3 text-slate-400 text-sm">
            <span className="h-2 w-2 rounded-full bg-blue-500 animate-ping"></span>
            <span>Loading threat intelligence IOCs...</span>
          </div>
        </div>
      )}
      {error && <ErrorBanner message={error} />}
      {!loading && !error && (
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl shadow-sm overflow-hidden hover:border-slate-700 transition-all duration-200">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#1F2937] text-[10px] font-bold text-slate-400 uppercase tracking-wider bg-[#0B1329]">
                <th className="py-2.5 px-3.5">Indicator Value</th>
                <th className="py-2.5 px-3.5">Type</th>
                <th className="py-2.5 px-3.5">Threat Name</th>
                <th className="py-2.5 px-3.5">Confidence</th>
                <th className="py-2.5 px-3.5">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937]">
              {iocs.map((ioc) => (
                <tr key={ioc.indicator_id} className="hover:bg-[#1E293B]/60 transition-colors text-xs">
                  <td className="py-2 px-3.5 font-mono text-[11px] text-blue-400 font-semibold">{ioc.indicator_value}</td>
                  <td className="py-2 px-3.5 text-slate-300">{ioc.indicator_type}</td>
                  <td className="py-2 px-3.5 text-slate-200 font-semibold">{ioc.threat_name}</td>
                  <td className="py-2 px-3.5 text-slate-300 font-mono text-[11px]">{ioc.confidence}</td>
                  <td className="py-2 px-3.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_STYLE[ioc.severity]}`}>
                      {ioc.severity}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
