import { cn } from "./utils";

export const Card = ({ children, className }: { children: React.ReactNode; className?: string }) => (
  <div className={cn("bg-white rounded-xl border border-gray-200 shadow-sm p-6", className)}>
    {children}
  </div>
);
