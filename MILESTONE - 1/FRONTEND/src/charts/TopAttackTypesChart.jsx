import { Bar } from "react-chartjs-2";
import {
  Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip, Legend,
} from "chart.js";

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

export default function TopAttackTypesChart({ threats }) {
  const top = threats.slice(0, 6);

  const data = {
    labels: top.map((t) => t.event_type),
    datasets: [{
      label: "Occurrences",
      data: top.map((t) => t.count),
      backgroundColor: "#3B82F6",
      borderRadius: 6,
      maxBarThickness: 36,
    }],
  };

  const options = {
    indexAxis: "y",
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: "#0B1329",
        titleColor: "#F8FAFC",
        bodyColor: "#CBD5E1",
        borderColor: "#1F2937",
        borderWidth: 1,
      },
    },
    scales: {
      x: {
        beginAtZero: true,
        ticks: { font: { size: 10 }, color: "#94A3B8" },
        grid: { color: "#1E293B" },
      },
      y: {
        ticks: { font: { size: 11, weight: 500 }, color: "#CBD5E1" },
        grid: { display: false },
      },
    },
    maintainAspectRatio: false,
  };

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 shadow-sm h-full flex flex-col hover:border-slate-700 hover:-translate-y-0.5 transition-all duration-200">
      <h3 className="text-sm font-bold text-slate-100 mb-3 flex items-center justify-between">
        <span>Top Attack Types</span>
        <span className="text-xs font-normal text-slate-400">By Frequency</span>
      </h3>
      <div className="flex-1 min-h-[260px] md:min-h-[280px]">
        <Bar data={data} options={options} />
      </div>
    </div>
  );
}
