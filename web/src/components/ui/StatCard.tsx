import type { LucideIcon } from "lucide-react";
import { cn } from "./utils";

interface StatCardProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  color?: string;
  subLabel?: string;
}

export const StatCard = ({ label, value, icon: Icon, color = "bg-blue-500", subLabel }: StatCardProps) => (
  <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm flex items-center space-x-4">
    <div className={cn("p-3 rounded-lg flex-shrink-0 text-white shadow-inner", color)}>
      <Icon size={24} />
    </div>
    <div className="flex-1 min-w-0">
      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">{label}</p>
      <p className="text-2xl font-bold text-gray-900 tracking-tight font-mono tabular-nums leading-none">
        {value}
      </p>
      {subLabel && <p className="text-xs text-gray-400 mt-1">{subLabel}</p>}
    </div>
  </div>
);
