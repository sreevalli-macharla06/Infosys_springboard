import { useState } from "react";
import { NavLink } from "react-router-dom";
import {
  FiSearch,
  FiBell,
  FiUser,
  FiCalendar,
  FiActivity,
  FiSun,
  FiMoon,
  FiMenu,
  FiX,
  FiGrid,
  FiAlertTriangle,
  FiShield,
  FiLock,
  FiBarChart2,
  FiTrendingUp,
  FiGitCommit,
  FiLayers,
} from "react-icons/fi";
import { useTheme } from "../../context/ThemeContext";

const menuItems = [
  { icon: FiTrendingUp, label: "Risk Overview", to: "/dashboard/risk-overview" },
  { icon: FiAlertTriangle, label: "Priority Incidents", to: "/dashboard/incidents" },
  { icon: FiGitCommit, label: "Attack Chains", to: "/dashboard/attack-chains" },
  { icon: FiGrid, label: "Overview", to: "/dashboard" },
  { icon: FiShield, label: "AI Threat Detection", to: "/dashboard/detection" },
  { icon: FiActivity, label: "Security Events", to: "/dashboard/events" },
  { icon: FiLayers, label: "Threat Intelligence", to: "/dashboard/threat-intel" },
  { icon: FiLock, label: "Vulnerabilities", to: "/dashboard/vulnerabilities" },
  { icon: FiBarChart2, label: "Analytics", to: "/dashboard/analytics" },
];

const Header = () => {
  const { toggleTheme, isDark } = useTheme();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <header className="bg-[#0B1329] border-b border-[#1F2937] px-4 md:px-6 py-3 select-none relative z-30">
      {/* Top Row: Title + Status Chips & Compact Profile */}
      <div className="flex items-center justify-between gap-3">
        {/* Left Side: Title & Subtitle + Mobile Toggle */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle mobile menu"
            className="lg:hidden flex h-8 w-8 items-center justify-center rounded-lg border border-[#1F2937] bg-[#111827] text-slate-300 hover:text-white"
          >
            {mobileMenuOpen ? <FiX className="text-base" /> : <FiMenu className="text-base" />}
          </button>
          <div>
            <h1 className="text-lg md:text-2xl font-extrabold tracking-tight text-slate-100">
              Security Dashboard
            </h1>
            <p className="text-[11px] md:text-xs text-slate-400 font-medium">
              Real-time AI Threat Monitoring
            </p>
          </div>

          {/* Status Chips */}
          <div className="hidden sm:flex items-center gap-2 ml-2">
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

        {/* Right Side: Theme Toggle & Profile Badge */}
        <div className="flex items-center gap-2">
          <button
            onClick={toggleTheme}
            title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
            aria-label={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#1F2937] bg-[#111827] text-slate-300 hover:text-white hover:border-slate-700 transition-all duration-200 cursor-pointer"
          >
            {isDark ? (
              <FiSun className="text-sm text-amber-400" />
            ) : (
              <FiMoon className="text-sm text-blue-400" />
            )}
          </button>

          <button
            title="Notifications"
            className="relative flex h-8 w-8 items-center justify-center rounded-lg border border-[#1F2937] bg-[#111827] text-slate-300 hover:text-white hover:border-slate-700 transition-all duration-200"
          >
            <FiBell className="text-sm" />
            <span className="absolute top-1.5 right-1.5 h-1.5 w-1.5 rounded-full bg-red-500 ring-2 ring-[#111827]"></span>
          </button>

          <div className="flex items-center gap-2 rounded-lg border border-[#1F2937] bg-[#111827] px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:border-slate-700 transition-all duration-200 cursor-pointer">
            <div className="flex h-5 w-5 items-center justify-center rounded-full bg-blue-600 text-white text-[10px] shrink-0 font-bold">
              <FiUser />
            </div>
            <span className="font-semibold text-slate-200 hidden sm:inline">SOC Analyst</span>
            <span className="text-[10px] text-slate-400">▼</span>
          </div>
        </div>
      </div>

      {/* Search Bar */}
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

      {/* Mobile Navigation Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="lg:hidden mt-3 border-t border-[#1F2937] pt-3 pb-1 space-y-1">
          {menuItems.map((item) => (
            <NavLink
              key={item.label}
              to={item.to}
              end={item.to === "/dashboard"}
              onClick={() => setMobileMenuOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-semibold transition-all ${
                  isActive
                    ? "bg-blue-600 text-white shadow-md"
                    : "text-slate-300 hover:bg-[#111827]"
                }`
              }
            >
              <item.icon className="text-sm shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </div>
      )}
    </header>
  );
};

export default Header;