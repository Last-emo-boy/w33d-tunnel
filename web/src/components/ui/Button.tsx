import React from "react";
import { cn } from "./utils";
import type { LucideIcon } from "lucide-react";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "ghost";
  size?: "sm" | "md" | "lg";
  icon?: LucideIcon;
  isLoading?: boolean;
}

export const Button = ({
  children,
  className,
  variant = "primary",
  size = "md",
  icon: Icon,
  isLoading,
  disabled,
  ...props
}: ButtonProps) => {
  const baseStyles = "inline-flex items-center justify-center font-medium transition-all rounded-lg focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed";
  
  const variants = {
    primary: "bg-blue-600 text-white hover:bg-blue-700 shadow-sm hover:shadow-md",
    secondary: "bg-white text-gray-700 border border-gray-200 hover:bg-gray-50",
    danger: "bg-red-600 text-white hover:bg-red-700 shadow-sm",
    ghost: "text-gray-500 hover:text-gray-900 hover:bg-gray-100",
  };

  const sizes = {
    sm: "h-8 px-3 text-xs gap-1.5",
    md: "h-[42px] px-4 text-sm gap-2",
    lg: "h-12 px-6 text-base gap-2.5",
  };

  return (
    <button
      className={cn(baseStyles, variants[variant], sizes[size], className)}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading && <span className="animate-spin mr-2">⟳</span>}
      {Icon && !isLoading && <Icon size={size === 'sm' ? 14 : 18} />}
      {children}
    </button>
  );
};
