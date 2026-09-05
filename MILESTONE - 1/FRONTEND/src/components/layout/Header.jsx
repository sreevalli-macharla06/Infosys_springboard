import {
  FiSearch,
  FiBell,
  FiUser,
  FiCalendar,
  FiActivity,
} from "react-icons/fi";

const Header = () => {
  return (
    <header className="bg-[#0B1329] border-b border-[#1F2937] px-4 md:px-6 py-3 select-none">
      {/* ================= Top Row: Title + Status Chips & Compact Profile ================= */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Left Side: Title & Subtitle + Inline Status Chips */}
        <div className="flex flex-wrap items-center gap-4">
          <div>
            <h1 className="text-xl md:text-2xl font-extrabold tracking-tight text-slate-100">
              Security Dashboard
            </h1>
            <p className="text-xs text-slate-400 font-medium">
              Real-time AI Threat Monitoring
            </p>
          </div>

          {/* Status Chips on the right side of title */}
          <div className="hidden sm:flex items-center gap-2">
            <div className="flex items-center gap-1.5 rounded-lg border border-[#1F2937] bg-[#111827] px-2.5 py-1 text-xs font-medium text-slate-300">
              <FiActivity className="text-emerald-400 text-xs" />
              <span>Live Feed</span>
            </div>
            <div className="flex items-center gap-1.5 rounded-lg border border-[#1F2937] bg-[#111827] px-2.5 py-1 text-xs font-medium text-slate-300">
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>System Online</span>
            </div>
            <div className="flex items-center gap-1.5 rounded-lg border border-[#1F2937] bg-[#111827] px-2.5 py-1 text-xs font-medium text-slate-300">
              <FiCalendar className="text-blue-400 text-xs" />
              <span>{new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}</span>
            </div>
          </div>
        </div>

        {/* Right Side: Compact Notification Bell & Profile Badge */}
        <div className="flex items-center gap-2">
          {/* Notification Bell */}
          <button
            title="Notifications"
            className="relative flex h-8 w-8 items-center justify-center rounded-lg border border-[#1F2937] bg-[#111827] text-slate-300 hover:text-white hover:border-slate-700 transition-all duration-200"
          >
            <FiBell className="text-sm" />
            <span className="absolute top-1.5 right-1.5 h-1.5 w-1.5 rounded-full bg-red-500 ring-2 ring-[#111827]"></span>
          </button>

          {/* Compact Profile Badge */}
          <div className="flex items-center gap-2 rounded-lg border border-[#1F2937] bg-[#111827] px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:border-slate-700 transition-all duration-200 cursor-pointer">
            <div className="flex h-5 w-5 items-center justify-center rounded-full bg-blue-600 text-white text-[10px] shrink-0 font-bold">
              <FiUser />
            </div>
            <span className="font-semibold text-slate-200">SOC Analyst</span>
            <span className="text-[10px] text-slate-400">▼</span>
          </div>
        </div>
      </div>

      {/* ================= Bottom Row: Search Bar (Placeholder) ================= */}
      <div className="mt-2.5">
        <div className="flex items-center rounded-lg border border-[#1F2937] bg-[#111827] px-3 py-1.5 transition-all duration-200 focus-within:border-blue-500 focus-within:ring-1 focus-within:ring-blue-500/20">
          <FiSearch className="text-sm text-slate-400 shrink-0" />
          <input
            type="text"
            placeholder="Search security events, IP addresses, indicators, vulnerabilities..."
            className="ml-2 w-full bg-transparent text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none"
          />
        </div>
      </div>
    </header>
  );
};

export default Header;