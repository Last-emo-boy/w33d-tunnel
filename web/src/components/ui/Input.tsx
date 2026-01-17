import React from "react";
import { cn } from "./utils";
import type { LucideIcon } from "lucide-react";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  icon?: LucideIcon;
}

export const Input = ({ label, icon: Icon, className, ...props }: InputProps) => (
  <div className="space-y-1 w-full">
    {label && (
      <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2 ml-1">
        {label}
      </label>
    )}
    <div className="relative group">
      {Icon && (
        <Icon
          size={18}
          className="absolute left-3.5 top-3 text-gray-400 group-focus-within:text-blue-500 transition-colors"
        />
      )}
      <input
        className={cn(
          "w-full bg-white border border-gray-200 rounded-lg text-sm text-gray-900 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all h-[42px]",
          Icon ? "pl-11 pr-4" : "px-4",
          className
        )}
        {...props}
      />
    </div>
  </div>
);
