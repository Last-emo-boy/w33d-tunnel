import { cn } from "./utils";

export const Badge = ({ children, variant = "default", className }: { children: React.ReactNode, variant?: "success" | "warning" | "error" | "default", className?: string }) => {
  const variants = {
    success: "bg-green-50 text-green-700 border-green-200",
    warning: "bg-yellow-50 text-yellow-700 border-yellow-200",
    error: "bg-red-50 text-red-700 border-red-200",
    default: "bg-gray-100 text-gray-700 border-gray-200",
  };

  return (
    <span className={cn("px-2 py-0.5 rounded-full text-xs font-medium border", variants[variant], className)}>
      {children}
    </span>
  );
};
