import { useState, useEffect, useRef } from 'react';
import { LoadConfig, Connect, Disconnect } from "../wailsjs/go/main/App";
import { EventsOn } from "../wailsjs/runtime/runtime";
import { Shield, Zap, Power, Activity, Settings, Terminal, Globe, ArrowUp, ArrowDown } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: any[]) {
  return twMerge(clsx(inputs));
}

// --- Components ---

const Card = ({ children, className }: any) => (
  <div className={cn("bg-white rounded-xl border border-gray-200 shadow-sm p-5", className)}>
    {children}
  </div>
);

const Label = ({ children }: any) => (
  <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2 ml-1">
    {children}
  </label>
);

const Input = ({ label, icon: Icon, ...props }: any) => (
  <div className="space-y-1 w-full">
    {label && <Label>{label}</Label>}
    <div className="relative group">
      {Icon && <Icon size={18} className="absolute left-3.5 top-3 text-gray-400 group-focus-within:text-blue-500 transition-colors" />}
      <input 
        className={cn(
          "w-full bg-white border border-gray-200 rounded-lg text-sm text-gray-900 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all",
          "h-[42px]", // Fixed height
          Icon ? "pl-11 pr-4" : "px-4"
        )}
        {...props}
      />
    </div>
  </div>
);

const StatCard = ({ label, value, icon: Icon, color, subLabel }: any) => (
  <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm flex items-center space-x-4 h-[84px]">
    <div className={cn("p-3 rounded-lg flex-shrink-0", color)}>
      <Icon size={22} className="text-white" />
    </div>
    <div className="flex-1 min-w-0 flex flex-col justify-center">
      <p className="text-xs font-medium text-gray-500 uppercase tracking-wide truncate">{label}</p>
      <p className="text-xl font-bold text-gray-900 tracking-tight font-mono tabular-nums leading-tight">
        {value}
      </p>
    </div>
  </div>
);

const ToggleButton = ({ active, onClick, disabled, label }: any) => (
  <button
    onClick={onClick}
    disabled={disabled}
    className={cn(
      "w-full h-[42px] px-4 rounded-lg text-sm font-medium transition-all border flex items-center justify-center space-x-2.5",
      active 
        ? "bg-blue-50 border-blue-200 text-blue-700" 
        : "bg-white border-gray-200 text-gray-600 hover:bg-gray-50 hover:border-gray-300",
      disabled && "opacity-60 cursor-not-allowed"
    )}
  >
    <Globe size={18} className={cn(active ? "text-blue-600" : "text-gray-400")} />
    <span className="flex-1 text-left">{label}</span>
    <div className={cn(
      "w-2.5 h-2.5 rounded-full transition-colors flex-shrink-0", 
      active ? "bg-blue-500 shadow-[0_0_0_2px_rgba(59,130,246,0.2)]" : "bg-gray-300"
    )} />
  </button>
);

// --- Helpers ---

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

function App() {
  const [config, setConfig] = useState({ sub_url: '', socks_addr: ':1080', global_proxy: false });
  const [status, setStatus] = useState('disconnected');
  const [stats, setStats] = useState({ bytes_tx: 0, bytes_rx: 0 });
  const [logs, setLogs] = useState<string[]>([]);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    LoadConfig().then(setConfig);
    EventsOn("log", (msg: string) => setLogs(p => [...p, msg].slice(-1000)));
    EventsOn("stats", (s: any) => setStats(s));
    EventsOn("disconnected", () => setStatus('disconnected'));
    EventsOn("error", (err: string) => {
        setStatus('disconnected');
        setLogs(p => [...p, `ERROR: ${err}`]);
    });
  }, []);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const toggleConnect = async () => {
    if (status === 'connected') {
      await Disconnect();
      setStatus('disconnected');
    } else {
      setStatus('connecting');
      try {
        await Connect(config);
        setStatus('connected');
      } catch (e: any) {
        setStatus('disconnected');
        setLogs(p => [...p, `ERROR: ${e}`]);
      }
    }
  };

  return (
    <div className="min-h-screen bg-gray-50/50 text-gray-900 font-sans selection:bg-blue-100 flex flex-col">
      
      {/* Header */}
      <div className="bg-white/80 backdrop-blur-md border-b border-gray-200/60 px-6 py-4 flex items-center justify-between sticky top-0 z-20 shadow-sm">
        <div className="flex items-center space-x-3 group cursor-default">
          <div className="bg-gradient-to-br from-blue-600 to-indigo-600 p-2 rounded-xl shadow-lg shadow-blue-500/20 transition-transform group-hover:scale-105 group-hover:rotate-3">
            <Shield className="text-white" size={20} strokeWidth={2.5} />
          </div>
          <div>
            <h1 className="text-lg font-extrabold tracking-tight text-gray-900 leading-none">
              w33d <span className="text-blue-600">Tunnel</span>
            </h1>
            <p className="text-[10px] text-gray-400 font-medium tracking-wide mt-0.5">SECURE PROXY CLIENT</p>
          </div>
        </div>
        
        <div className={cn(
          "flex items-center space-x-2 px-3 py-1.5 rounded-full border shadow-sm transition-all duration-500",
          status === 'connected' ? "bg-green-50 border-green-200 text-green-700" :
          status === 'connecting' ? "bg-amber-50 border-amber-200 text-amber-700" :
          "bg-gray-100 border-gray-200 text-gray-500"
        )}>
           <div className={cn("h-2 w-2 rounded-full", 
              status === 'connected' ? "bg-green-500 animate-pulse shadow-[0_0_8px_rgba(34,197,94,0.5)]" : 
              status === 'connecting' ? "bg-amber-500 animate-bounce" : "bg-gray-400"
           )} />
           <span className="text-[11px] font-bold uppercase tracking-wider">
             {status}
           </span>
        </div>
      </div>

      <div className="flex-1 p-6 max-w-lg mx-auto w-full space-y-6 flex flex-col">
        
        {/* Stats Section */}
        <div className="grid grid-cols-2 gap-4">
          <StatCard 
            label="Total Upload" 
            value={formatBytes(stats.bytes_tx)} 
            icon={ArrowUp} 
            color="from-orange-400 to-pink-500" 
            subLabel="Outbound Traffic"
          />
          <StatCard 
            label="Total Download" 
            value={formatBytes(stats.bytes_rx)} 
            icon={ArrowDown} 
            color="from-emerald-400 to-teal-500" 
            subLabel="Inbound Traffic"
          />
        </div>

        {/* Configuration Card */}
        <Card className="space-y-6 flex-none">
          <div className="flex items-center space-x-2 mb-4 pb-4 border-b border-gray-100">
             <Settings size={18} className="text-gray-400" />
             <h2 className="text-sm font-bold text-gray-700 uppercase tracking-wider">Connection Settings</h2>
          </div>
          
          <div className="space-y-5">
            <Input 
              label="Subscription Link" 
              icon={Activity}
              placeholder="https://cloud.w33d.xyz/api/subscribe?token=..." 
              value={config.sub_url}
              onChange={(e: any) => setConfig({...config, sub_url: e.target.value})}
              disabled={status !== 'disconnected'}
            />
            
            <div className="grid grid-cols-[1.5fr_1fr] gap-4 items-end">
              <Input 
                label="Local Port" 
                icon={Zap}
                placeholder=":1080" 
                value={config.socks_addr}
                onChange={(e: any) => setConfig({...config, socks_addr: e.target.value})}
                disabled={status !== 'disconnected'}
              />
              
              <div className="space-y-1">
                <Label>System Proxy</Label>
                <ToggleButton 
                  active={config.global_proxy}
                  label={config.global_proxy ? "Active" : "Off"}
                  disabled={status !== 'disconnected'}
                  onClick={() => setConfig({...config, global_proxy: !config.global_proxy})}
                />
              </div>
            </div>
          </div>

          <div className="pt-4">
            <button
              onClick={toggleConnect}
              disabled={status === 'connecting'}
              className={cn(
                "w-full py-4 rounded-xl text-white font-bold shadow-lg transition-all transform active:scale-[0.98] flex items-center justify-center space-x-3 group relative overflow-hidden",
                status === 'connected' 
                  ? "bg-gradient-to-r from-red-500 to-pink-600 hover:shadow-red-500/30" 
                  : "bg-gradient-to-r from-blue-600 to-indigo-600 hover:shadow-blue-600/30"
              )}
            >
              <div className="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300 rounded-xl" />
              <Power size={22} className={cn("transition-transform", status === 'connecting' && "animate-spin")} />
              <span className="text-lg tracking-wide relative">
                {status === 'connected' ? 'DISCONNECT' : status === 'connecting' ? 'CONNECTING...' : 'CONNECT'}
              </span>
            </button>
          </div>
        </Card>

        {/* Logs Terminal */}
        <Card className="flex-1 min-h-[200px] p-0 overflow-hidden flex flex-col bg-[#1a1b26] border-gray-800 shadow-xl">
           <div className="px-4 py-2.5 border-b border-white/10 bg-white/5 flex items-center justify-between">
             <div className="flex items-center space-x-2">
               <Terminal size={14} className="text-gray-400" />
               <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-wider">System Logs</h3>
             </div>
             <div className="flex space-x-1.5">
               <div className="w-2.5 h-2.5 rounded-full bg-red-500/20 border border-red-500/50" />
               <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/20 border border-yellow-500/50" />
               <div className="w-2.5 h-2.5 rounded-full bg-green-500/20 border border-green-500/50" />
             </div>
           </div>
           <div className="flex-1 overflow-y-auto p-4 font-mono text-[11px] leading-relaxed scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
              {logs.length === 0 && (
                <div className="h-full flex items-center justify-center text-gray-600 italic">
                  Waiting for activity...
                </div>
              )}
              {logs.map((log, i) => (
                <div key={i} className="group hover:bg-white/5 -mx-2 px-2 py-0.5 rounded transition-colors flex">
                  <span className="text-gray-600 select-none mr-3 w-[65px] flex-shrink-0">
                    {new Date().toLocaleTimeString([], {hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit'})}
                  </span>
                  <span className={cn(
                    "break-all",
                    log.includes("ERROR") ? "text-red-400 font-bold" : 
                    log.includes("Connected") ? "text-green-400" :
                    log.includes("Connecting") ? "text-blue-400" :
                    "text-gray-300"
                  )}>
                    {log}
                  </span>
                </div>
              ))}
              <div ref={logsEndRef} />
           </div>
        </Card>

        <div className="text-center pb-2">
            <p className="text-[10px] font-medium text-gray-400 hover:text-gray-600 transition-colors cursor-default">
              v1.0.0 • w33d Tunnel
            </p>
        </div>

      </div>
    </div>
  )
}

export default App
