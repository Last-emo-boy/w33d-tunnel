import { useState, useEffect, useRef } from 'react';
import { ControllerApplyKernelConfig, ControllerGetKernelConfig, ControllerGetKernelRuntimeStats, ControllerResetKernelRuntimeStats, LoadConfig, Connect, Disconnect, CreateKernelProfile, DeleteKernelProfile, GetKernelControllerState, GetKernelProfiles, GetKernelRuntimeStats, ListKernelProfileRevisions, LoadKernelProfile, ProbeKernelRoute, ResetKernelRuntimeStats, RollbackKernelProfile, SaveKernelProfile, SetActiveKernelProfile, ValidateKernelConfig } from "../wailsjs/go/main/App";
import { EventsOn } from "../wailsjs/runtime/runtime";
import { Shield, Zap, Power, Activity, Settings, Terminal, Globe, ArrowUp, ArrowDown, FileCode2 } from 'lucide-react';
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

type KernelValidationResult = {
  valid: boolean;
  message: string;
  outbounds: number;
  rules: number;
  default_target: string;
};

type KernelProfileState = {
  active: string;
  profiles: string[];
};

type KernelProfileRevision = {
  id: string;
  created_at: string;
  bytes: number;
};

type KernelRouteProbeResult = {
  ok: boolean;
  message: string;
  matched: boolean;
  rule: string;
  outbound: string;
  adapter_type: string;
  trace: Array<{
    index: number;
    rule: string;
    outbound: string;
    matched: boolean;
  }>;
};

type KernelRuntimeStats = {
  profile: string;
  version: number;
  total_routes: number;
  matched_routes: number;
  default_routes: number;
  last_rule: string;
  last_outbound: string;
  outbound_hits: Record<string, number>;
  adapter_health: Record<string, string>;
};

type KernelControllerState = {
  running: boolean;
  profile: string;
  url: string;
  require_auth: boolean;
  write: boolean;
};

function App() {
  const [config, setConfig] = useState({ sub_url: '', socks_addr: ':1080', global_proxy: false, auto_start: false });
  const [status, setStatus] = useState('disconnected');
  const [stats, setStats] = useState({ bytes_tx: 0, bytes_rx: 0 });
  const [logs, setLogs] = useState<string[]>([]);
  const [kernelConfig, setKernelConfig] = useState('');
  const [kernelProfiles, setKernelProfiles] = useState<string[]>([]);
  const [activeKernelProfile, setActiveKernelProfile] = useState<string>('');
  const [newKernelProfileName, setNewKernelProfileName] = useState('');
  const [kernelFormat, setKernelFormat] = useState<'yaml' | 'json'>('yaml');
  const [kernelRevisions, setKernelRevisions] = useState<KernelProfileRevision[]>([]);
  const [selectedKernelRevision, setSelectedKernelRevision] = useState('');
  const [kernelValidation, setKernelValidation] = useState<KernelValidationResult | null>(null);
  const [kernelProbeHost, setKernelProbeHost] = useState('');
  const [kernelProbeIP, setKernelProbeIP] = useState('');
  const [kernelProbePort, setKernelProbePort] = useState('443');
  const [kernelProbeNetwork, setKernelProbeNetwork] = useState<'tcp' | 'udp'>('tcp');
  const [kernelProbeResult, setKernelProbeResult] = useState<KernelRouteProbeResult | null>(null);
  const [kernelRuntimeStats, setKernelRuntimeStats] = useState<KernelRuntimeStats | null>(null);
  const [kernelControllerState, setKernelControllerState] = useState<KernelControllerState | null>(null);
  const [kernelBusy, setKernelBusy] = useState(false);
  const logsEndRef = useRef<HTMLDivElement>(null);

  const refreshKernelProfiles = async () => {
    const state = await GetKernelProfiles() as KernelProfileState;
    setKernelProfiles(state.profiles || []);
    setActiveKernelProfile(state.active || '');
    const content = await LoadKernelProfile(state.active || '');
    setKernelConfig(content);
    await refreshKernelControllerState(state.active || '');
    const revisions = await ListKernelProfileRevisions(state.active || '') as KernelProfileRevision[];
    setKernelRevisions(revisions || []);
    setSelectedKernelRevision((revisions && revisions.length > 0) ? revisions[0].id : '');
  };

  const refreshKernelRevisions = async (profile: string) => {
    const revisions = await ListKernelProfileRevisions(profile || '') as KernelProfileRevision[];
    setKernelRevisions(revisions || []);
    setSelectedKernelRevision((revisions && revisions.length > 0) ? revisions[0].id : '');
  };

  const refreshKernelControllerState = async (profile: string) => {
    if (!profile) {
      setKernelControllerState(null);
      return;
    }
    const state = await GetKernelControllerState(profile) as KernelControllerState;
    setKernelControllerState(state);
  };

  useEffect(() => {
    LoadConfig().then(setConfig);
    refreshKernelProfiles().catch((e) => {
      setLogs(p => [...p, `[KERNEL] Failed to load profiles: ${e}`]);
    });
    EventsOn("log", (msg: string) => setLogs(p => [...p, msg].slice(-1000)));
    EventsOn("stats", (s: any) => setStats(s));
    EventsOn("disconnected", () => setStatus('disconnected'));
    EventsOn("error", (err: string) => {
        setStatus('disconnected');
        setLogs(p => [...p, `ERROR: ${err}`]);
    });
  }, []);

  useEffect(() => {
    if (!activeKernelProfile) return;
    let disposed = false;
    const tick = async () => {
      try {
        const s = await ControllerGetKernelRuntimeStats(activeKernelProfile) as KernelRuntimeStats;
        if (!disposed) setKernelRuntimeStats(s);
      } catch (e) {
        try {
          const direct = await GetKernelRuntimeStats(activeKernelProfile) as KernelRuntimeStats;
          if (!disposed) setKernelRuntimeStats(direct);
        } catch (_) {
        }
      }
    };
    tick();
    const id = setInterval(tick, 2000);
    return () => {
      disposed = true;
      clearInterval(id);
    };
  }, [activeKernelProfile]);

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

  const handleKernelValidate = async () => {
    setKernelBusy(true);
    try {
      const result = await ValidateKernelConfig(kernelConfig, kernelFormat);
      setKernelValidation(result as KernelValidationResult);
      setLogs(p => [...p, result.valid ? "[KERNEL] Config validation passed" : `[KERNEL] Validation failed: ${result.message}`]);
    } catch (e: any) {
      setKernelValidation({ valid: false, message: String(e), outbounds: 0, rules: 0, default_target: '' });
      setLogs(p => [...p, `[KERNEL] Validation error: ${e}`]);
    } finally {
      setKernelBusy(false);
    }
  };

  const handleKernelSave = async () => {
    setKernelBusy(true);
    try {
      await SaveKernelProfile(activeKernelProfile, kernelConfig);
      await refreshKernelRevisions(activeKernelProfile);
      setLogs(p => [...p, `[KERNEL] Config saved (${activeKernelProfile})`]);
    } catch (e: any) {
      setLogs(p => [...p, `[KERNEL] Save failed: ${e}`]);
    } finally {
      setKernelBusy(false);
    }
  };

  const handleKernelProfileSwitch = async (profile: string) => {
    if (!profile) return;
    setKernelBusy(true);
    try {
      await SetActiveKernelProfile(profile);
      const content = await LoadKernelProfile(profile);
      setActiveKernelProfile(profile);
      setKernelConfig(content);
      setKernelValidation(null);
      await refreshKernelControllerState(profile);
      await refreshKernelRevisions(profile);
      setLogs(p => [...p, `[KERNEL] Switched active profile -> ${profile}`]);
    } catch (e: any) {
      setLogs(p => [...p, `[KERNEL] Switch profile failed: ${e}`]);
    } finally {
      setKernelBusy(false);
    }
  };

  const handleKernelProfileCreate = async () => {
    const name = newKernelProfileName.trim();
    if (!name) return;
    setKernelBusy(true);
    try {
      await CreateKernelProfile(name);
      await refreshKernelProfiles();
      await SetActiveKernelProfile(name);
      const content = await LoadKernelProfile(name);
      setActiveKernelProfile(name);
      setKernelConfig(content);
      setNewKernelProfileName('');
      setKernelValidation(null);
      await refreshKernelControllerState(name);
      await refreshKernelRevisions(name);
      setLogs(p => [...p, `[KERNEL] Created profile: ${name}`]);
    } catch (e: any) {
      setLogs(p => [...p, `[KERNEL] Create profile failed: ${e}`]);
    } finally {
      setKernelBusy(false);
    }
  };

  const handleKernelProfileDelete = async () => {
    if (!activeKernelProfile || activeKernelProfile === "default") return;
    setKernelBusy(true);
    try {
      await DeleteKernelProfile(activeKernelProfile);
      await refreshKernelProfiles();
      setKernelValidation(null);
      setKernelRevisions([]);
      setSelectedKernelRevision('');
      setLogs(p => [...p, `[KERNEL] Deleted profile: ${activeKernelProfile}`]);
    } catch (e: any) {
      setLogs(p => [...p, `[KERNEL] Delete profile failed: ${e}`]);
    } finally {
      setKernelBusy(false);
    }
  };

  const handleKernelProbe = async () => {
    setKernelBusy(true);
    try {
      const port = parseInt(kernelProbePort, 10) || 0;
      const result = await ProbeKernelRoute(activeKernelProfile, kernelProbeHost, kernelProbeIP, port, kernelProbeNetwork) as KernelRouteProbeResult;
      setKernelProbeResult(result);
      if (result.ok) {
        setLogs(p => [...p, `[KERNEL] Probe -> outbound=${result.outbound}, rule=${result.rule}`]);
      } else {
        setLogs(p => [...p, `[KERNEL] Probe failed: ${result.message}`]);
      }
    } catch (e: any) {
      setKernelProbeResult({
        ok: false,
        message: String(e),
        matched: false,
        rule: "",
        outbound: "",
        adapter_type: "",
        trace: [],
      });
      setLogs(p => [...p, `[KERNEL] Probe error: ${e}`]);
    } finally {
      setKernelBusy(false);
    }
  };

  const handleKernelStatsReset = async () => {
    if (!activeKernelProfile) return;
    setKernelBusy(true);
    try {
      const s = await ControllerResetKernelRuntimeStats(activeKernelProfile) as KernelRuntimeStats;
      setKernelRuntimeStats(s);
      setLogs(p => [...p, `[KERNEL] Controller runtime reset (${activeKernelProfile})`]);
    } catch (e: any) {
      try {
        await ResetKernelRuntimeStats(activeKernelProfile);
        const fallback = await GetKernelRuntimeStats(activeKernelProfile) as KernelRuntimeStats;
        setKernelRuntimeStats(fallback);
        setLogs(p => [...p, `[KERNEL] Fallback runtime reset (${activeKernelProfile})`]);
      } catch (fallbackErr: any) {
        setLogs(p => [...p, `[KERNEL] Reset stats failed: ${fallbackErr || e}`]);
      }
    } finally {
      setKernelBusy(false);
    }
  };

  const handleControllerRefreshRuntime = async () => {
    if (!activeKernelProfile) return;
    setKernelBusy(true);
    try {
      const s = await ControllerGetKernelRuntimeStats(activeKernelProfile) as KernelRuntimeStats;
      setKernelRuntimeStats(s);
      await refreshKernelControllerState(activeKernelProfile);
      setLogs(p => [...p, `[KERNEL] Controller runtime refreshed (${activeKernelProfile})`]);
    } catch (e: any) {
      setLogs(p => [...p, `[KERNEL] Controller runtime refresh failed: ${e}`]);
    } finally {
      setKernelBusy(false);
    }
  };

  const handleControllerLoadConfig = async () => {
    if (!activeKernelProfile) return;
    setKernelBusy(true);
    try {
      const content = await ControllerGetKernelConfig(activeKernelProfile);
      setKernelConfig(content);
      setKernelFormat('json');
      setKernelValidation(null);
      setLogs(p => [...p, `[KERNEL] Controller config loaded as JSON (${activeKernelProfile})`]);
    } catch (e: any) {
      setLogs(p => [...p, `[KERNEL] Controller config load failed: ${e}`]);
    } finally {
      setKernelBusy(false);
    }
  };

  const handleControllerApplyConfig = async () => {
    if (!activeKernelProfile) return;
    setKernelBusy(true);
    try {
      await ControllerApplyKernelConfig(activeKernelProfile, kernelFormat, kernelConfig);
      const s = await ControllerGetKernelRuntimeStats(activeKernelProfile) as KernelRuntimeStats;
      setKernelRuntimeStats(s);
      await refreshKernelControllerState(activeKernelProfile);
      await refreshKernelRevisions(activeKernelProfile);
      setLogs(p => [...p, `[KERNEL] Controller applied config to runtime (${activeKernelProfile})`]);
    } catch (e: any) {
      setLogs(p => [...p, `[KERNEL] Controller apply failed: ${e}`]);
    } finally {
      setKernelBusy(false);
    }
  };

  const handleKernelRollback = async () => {
    if (!activeKernelProfile || !selectedKernelRevision) return;
    setKernelBusy(true);
    try {
      await RollbackKernelProfile(activeKernelProfile, selectedKernelRevision);
      const content = await LoadKernelProfile(activeKernelProfile);
      setKernelConfig(content);
      setKernelValidation(null);
      await refreshKernelRevisions(activeKernelProfile);
      setLogs(p => [...p, `[KERNEL] Rolled back profile ${activeKernelProfile} to revision ${selectedKernelRevision}`]);
    } catch (e: any) {
      setLogs(p => [...p, `[KERNEL] Rollback failed: ${e}`]);
    } finally {
      setKernelBusy(false);
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
            
            <div className="grid grid-cols-[1.5fr_1fr_1fr] gap-4 items-end">
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

              <div className="space-y-1">
                <Label>Auto Start</Label>
                <ToggleButton 
                  active={config.auto_start}
                  label={config.auto_start ? "On" : "Off"}
                  disabled={status !== 'disconnected'}
                  onClick={() => setConfig({...config, auto_start: !config.auto_start})}
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

        {/* Kernel Config Card */}
        <Card className="space-y-4 flex-none">
          <div className="flex items-center justify-between mb-2 pb-2 border-b border-gray-100">
            <div className="flex items-center space-x-2">
              <FileCode2 size={18} className="text-gray-400" />
              <h2 className="text-sm font-bold text-gray-700 uppercase tracking-wider">Kernel Config</h2>
            </div>
            <div className="flex items-center space-x-2 text-xs">
              <button
                className={cn("px-2.5 py-1 rounded border", kernelFormat === 'yaml' ? "bg-blue-50 border-blue-300 text-blue-700" : "bg-white border-gray-200 text-gray-600")}
                onClick={() => setKernelFormat('yaml')}
              >
                YAML
              </button>
              <button
                className={cn("px-2.5 py-1 rounded border", kernelFormat === 'json' ? "bg-blue-50 border-blue-300 text-blue-700" : "bg-white border-gray-200 text-gray-600")}
                onClick={() => setKernelFormat('json')}
              >
                JSON
              </button>
            </div>
          </div>

          <div className="grid grid-cols-[1fr_auto_auto] gap-2">
            <select
              className="h-9 rounded-lg border border-gray-300 bg-white px-2 text-sm"
              value={activeKernelProfile}
              onChange={(e: any) => handleKernelProfileSwitch(e.target.value)}
              disabled={kernelBusy}
            >
              {kernelProfiles.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
            <button
              className="h-9 px-3 rounded-lg border border-gray-300 bg-white text-sm hover:bg-gray-50 disabled:opacity-50"
              onClick={handleKernelProfileDelete}
              disabled={kernelBusy || activeKernelProfile === "default"}
            >
              Delete
            </button>
            <button
              className="h-9 px-3 rounded-lg border border-gray-300 bg-white text-sm hover:bg-gray-50 disabled:opacity-50"
              onClick={refreshKernelProfiles}
              disabled={kernelBusy}
            >
              Refresh
            </button>
          </div>

          <div className="grid grid-cols-[1fr_auto] gap-2">
            <input
              className="h-9 rounded-lg border border-gray-300 bg-white px-2 text-sm"
              placeholder="new profile name (letters/numbers/-_.)"
              value={newKernelProfileName}
              onChange={(e: any) => setNewKernelProfileName(e.target.value)}
              disabled={kernelBusy}
            />
            <button
              className="h-9 px-3 rounded-lg bg-blue-600 text-white text-sm hover:bg-blue-700 disabled:opacity-50"
              onClick={handleKernelProfileCreate}
              disabled={kernelBusy || !newKernelProfileName.trim()}
            >
              Create
            </button>
          </div>

          <div className="grid grid-cols-[1fr_auto_auto] gap-2 items-center">
            <select
              className="h-9 rounded-lg border border-gray-300 bg-white px-2 text-sm"
              value={selectedKernelRevision}
              onChange={(e: any) => setSelectedKernelRevision(e.target.value)}
              disabled={kernelBusy || kernelRevisions.length === 0}
            >
              {kernelRevisions.length === 0 && (
                <option value="">no revisions</option>
              )}
              {kernelRevisions.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.created_at} ({r.bytes}B)
                </option>
              ))}
            </select>
            <button
              className="h-9 px-3 rounded-lg border border-gray-300 bg-white text-sm hover:bg-gray-50 disabled:opacity-50"
              onClick={() => refreshKernelRevisions(activeKernelProfile)}
              disabled={kernelBusy || !activeKernelProfile}
            >
              Revisions
            </button>
            <button
              className="h-9 px-3 rounded-lg bg-amber-600 text-white text-sm hover:bg-amber-700 disabled:opacity-50"
              onClick={handleKernelRollback}
              disabled={kernelBusy || !activeKernelProfile || !selectedKernelRevision}
            >
              Rollback
            </button>
          </div>

          <textarea
            className="w-full h-48 bg-gray-950 text-gray-100 text-xs font-mono rounded-lg p-3 border border-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
            value={kernelConfig}
            onChange={(e: any) => setKernelConfig(e.target.value)}
            spellCheck={false}
          />

          <div className="flex items-center justify-between gap-3">
            <div className="text-xs text-gray-500">
              Native desktop kernel config editor (profile: {activeKernelProfile || "none"}).
            </div>
            <div className="flex items-center gap-2">
              <button
                className="px-3 py-2 rounded-lg border border-gray-300 text-gray-700 text-sm hover:bg-gray-50 disabled:opacity-50"
                onClick={handleKernelValidate}
                disabled={kernelBusy}
              >
                Validate
              </button>
              <button
                className="px-3 py-2 rounded-lg bg-blue-600 text-white text-sm hover:bg-blue-700 disabled:opacity-50"
                onClick={handleKernelSave}
                disabled={kernelBusy}
              >
                Save
              </button>
              <button
                className="px-3 py-2 rounded-lg bg-indigo-600 text-white text-sm hover:bg-indigo-700 disabled:opacity-50"
                onClick={handleControllerApplyConfig}
                disabled={kernelBusy || !activeKernelProfile}
              >
                Controller Apply
              </button>
            </div>
          </div>

          <div className="rounded-lg border border-indigo-200 bg-indigo-50/40 px-3 py-2 text-xs text-indigo-900 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold">Local Controller</span>
              <span className="font-mono text-[11px]">
                {kernelControllerState?.running ? `running@${kernelControllerState.url}` : "not running"}
              </span>
            </div>
            <div className="font-mono break-all">
              profile={kernelControllerState?.profile || activeKernelProfile || "-"} auth={String(kernelControllerState?.require_auth ?? false)} write={String(kernelControllerState?.write ?? false)}
            </div>
            <div className="flex items-center gap-2">
              <button
                className="px-2.5 py-1.5 rounded border border-indigo-300 bg-white text-indigo-700 text-[11px] hover:bg-indigo-50 disabled:opacity-50"
                onClick={handleControllerRefreshRuntime}
                disabled={kernelBusy || !activeKernelProfile}
              >
                Runtime
              </button>
              <button
                className="px-2.5 py-1.5 rounded border border-indigo-300 bg-white text-indigo-700 text-[11px] hover:bg-indigo-50 disabled:opacity-50"
                onClick={handleControllerLoadConfig}
                disabled={kernelBusy || !activeKernelProfile}
              >
                Load Config
              </button>
            </div>
          </div>

          {kernelValidation && (
            <div className={cn(
              "text-xs rounded-lg px-3 py-2 border",
              kernelValidation.valid ? "bg-green-50 border-green-200 text-green-700" : "bg-red-50 border-red-200 text-red-700"
            )}>
              {kernelValidation.valid
                ? `Valid. outbounds=${kernelValidation.outbounds}, rules=${kernelValidation.rules}, default=${kernelValidation.default_target}`
                : `Invalid: ${kernelValidation.message}`}
            </div>
          )}
        </Card>

        {/* Kernel Route Probe Card */}
        <Card className="space-y-3 flex-none">
          <div className="flex items-center space-x-2 mb-1 pb-2 border-b border-gray-100">
            <FileCode2 size={16} className="text-gray-400" />
            <h3 className="text-xs font-bold text-gray-700 uppercase tracking-wider">Kernel Route Probe</h3>
          </div>

          <div className="grid grid-cols-[1fr_1fr] gap-2">
            <input
              className="h-9 rounded-lg border border-gray-300 bg-white px-2 text-sm"
              placeholder="host (e.g. api.telegram.org)"
              value={kernelProbeHost}
              onChange={(e: any) => setKernelProbeHost(e.target.value)}
              disabled={kernelBusy}
            />
            <input
              className="h-9 rounded-lg border border-gray-300 bg-white px-2 text-sm"
              placeholder="ip (optional)"
              value={kernelProbeIP}
              onChange={(e: any) => setKernelProbeIP(e.target.value)}
              disabled={kernelBusy}
            />
          </div>

          <div className="grid grid-cols-[1fr_1fr_auto] gap-2">
            <input
              className="h-9 rounded-lg border border-gray-300 bg-white px-2 text-sm"
              placeholder="port"
              value={kernelProbePort}
              onChange={(e: any) => setKernelProbePort(e.target.value)}
              disabled={kernelBusy}
            />
            <select
              className="h-9 rounded-lg border border-gray-300 bg-white px-2 text-sm"
              value={kernelProbeNetwork}
              onChange={(e: any) => setKernelProbeNetwork(e.target.value as 'tcp' | 'udp')}
              disabled={kernelBusy}
            >
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
            </select>
            <button
              className="h-9 px-3 rounded-lg bg-indigo-600 text-white text-sm hover:bg-indigo-700 disabled:opacity-50"
              onClick={handleKernelProbe}
              disabled={kernelBusy}
            >
              Probe
            </button>
          </div>

          {kernelProbeResult && (
            <div className={cn(
              "text-xs rounded-lg px-3 py-2 border",
              kernelProbeResult.ok ? "bg-indigo-50 border-indigo-200 text-indigo-700" : "bg-red-50 border-red-200 text-red-700"
            )}>
              {kernelProbeResult.ok
                ? `outbound=${kernelProbeResult.outbound}, adapter=${kernelProbeResult.adapter_type}, rule=${kernelProbeResult.rule}, matched=${String(kernelProbeResult.matched)}`
                : `probe failed: ${kernelProbeResult.message}`}
            </div>
          )}

          {kernelProbeResult?.ok && kernelProbeResult.trace && kernelProbeResult.trace.length > 0 && (
            <div className="rounded-lg border border-indigo-200 bg-indigo-50/40 px-3 py-2 text-xs text-indigo-900 space-y-1">
              <div className="font-semibold">Rule Trace</div>
              {kernelProbeResult.trace.map((step, idx) => (
                <div key={`${step.index}-${idx}`} className={cn("font-mono break-all", step.matched ? "text-indigo-800" : "text-indigo-500")}>
                  {(step.index >= 0 ? `#${step.index + 1}` : "default")} {step.rule} =&gt; {step.outbound} [{step.matched ? "match" : "skip"}]
                </div>
              ))}
            </div>
          )}

          <div className="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2 text-xs text-gray-700 space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-semibold">Runtime Counters</span>
              <button
                className="px-2 py-1 rounded border border-gray-300 bg-white text-[11px] hover:bg-gray-50 disabled:opacity-50"
                onClick={handleKernelStatsReset}
                disabled={kernelBusy || !activeKernelProfile}
              >
                Reset
              </button>
            </div>
            <div>version={kernelRuntimeStats?.version ?? 0} total={kernelRuntimeStats?.total_routes ?? 0} matched={kernelRuntimeStats?.matched_routes ?? 0} default={kernelRuntimeStats?.default_routes ?? 0}</div>
            <div>last_outbound={kernelRuntimeStats?.last_outbound || "-"} last_rule={kernelRuntimeStats?.last_rule || "-"}</div>
            <div className="font-mono break-all">hits={JSON.stringify(kernelRuntimeStats?.outbound_hits || {})}</div>
            <div className="font-mono break-all">health={JSON.stringify(kernelRuntimeStats?.adapter_health || {})}</div>
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
