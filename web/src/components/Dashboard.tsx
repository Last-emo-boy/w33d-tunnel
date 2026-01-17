import { useEffect, useState } from 'react';
import { listUsers, createUser, listNodes } from '../api';
import { Copy, RefreshCw, UserPlus, Server, Users, Activity, Shield, LogOut, CheckCircle2, XCircle, Search } from 'lucide-react';
import { Card } from './ui/Card';
import { Button } from './ui/Button';
import { Input } from './ui/Input';
import { Badge } from './ui/Badge';
import { StatCard } from './ui/StatCard';

interface User {
  id: number;
  username: string;
  token: string;
  created_at: string;
  quota_bytes: number;
}

interface Node {
  id: string;
  name: string;
  addr: string;
  last_seen: string;
}

export default function Dashboard() {
  const [users, setUsers] = useState<User[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  
  // New User Form
  const [username, setUsername] = useState('');
  const [quota, setQuota] = useState(10);
  const [bandwidth, setBandwidth] = useState(0); // 0 = Unlimited
  const [showModal, setShowModal] = useState(false);
  const [creating, setCreating] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [uData, nData] = await Promise.all([listUsers(), listNodes()]);
      setUsers(uData);
      setNodes(nData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000); // Auto refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    try {
      // Convert MB/s to Bytes/s if needed, or input is Bytes/s
      // Let's assume input is MB/s for user friendliness
      const bwBytes = bandwidth * 1024 * 1024;
      await createUser(username, quota, bwBytes);
      setShowModal(false);
      setUsername('');
      setBandwidth(0);
      fetchData();
    } catch (err) {
      alert('Failed to create user');
    } finally {
      setCreating(false);
    }
  };

  const getSubLink = (token: string) => {
    const baseUrl = window.location.origin;
    return `${baseUrl}/api/subscribe?token=${token}`;
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    // Could add toast here
  };
  
  const isOnline = (lastSeen: string) => {
    const diff = new Date().getTime() - new Date(lastSeen).getTime();
    return diff < 120000; // 2 minutes
  };

  const filteredUsers = users.filter(u => 
    u.username.toLowerCase().includes(search.toLowerCase()) || 
    u.token.includes(search)
  );

  const totalQuota = users.reduce((acc, u) => acc + u.quota_bytes, 0);

  return (
    <div className="min-h-screen bg-gray-50 text-gray-900 font-sans">
      {/* Navbar */}
      <header className="bg-white border-b border-gray-200 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-blue-600 p-1.5 rounded-lg text-white">
              <Shield size={20} />
            </div>
            <h1 className="text-xl font-bold tracking-tight">w33d <span className="text-blue-600">Tunnel</span> <span className="text-xs font-normal text-gray-400 bg-gray-100 px-2 py-0.5 rounded-full ml-2">Admin Panel</span></h1>
          </div>
          <div className="flex items-center gap-4">
            <Button variant="secondary" size="sm" icon={RefreshCw} onClick={fetchData} isLoading={loading}>
              Refresh
            </Button>
            <div className="h-6 w-px bg-gray-200" />
            <button onClick={() => window.location.reload()} className="text-gray-400 hover:text-gray-600 transition-colors">
              <LogOut size={20} />
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        
        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard 
            label="Active Nodes" 
            value={nodes.filter(n => isOnline(n.last_seen)).length} 
            icon={Server} 
            color="bg-green-500"
            subLabel={`Total: ${nodes.length}`}
          />
          <StatCard 
            label="Total Tenants" 
            value={users.length} 
            icon={Users} 
            color="bg-blue-500"
          />
          <StatCard 
            label="Total Quota" 
            value={(totalQuota / 1024 / 1024 / 1024).toFixed(0)} 
            icon={Activity} 
            color="bg-purple-500"
            subLabel="GB Allocated"
          />
          <StatCard 
            label="System Status" 
            value="Healthy" 
            icon={CheckCircle2} 
            color="bg-teal-500"
            subLabel="All systems operational"
          />
        </div>

        {/* Nodes Section */}
        <section>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-bold text-gray-800 flex items-center gap-2">
              <Server size={20} className="text-gray-400" />
              Tunnel Nodes
            </h2>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {nodes.map(node => {
              const online = isOnline(node.last_seen);
              return (
                <Card key={node.id} className="hover:shadow-md transition-shadow relative overflow-hidden group">
                  <div className={`absolute top-0 left-0 w-1 h-full ${online ? 'bg-green-500' : 'bg-red-500'}`} />
                  <div className="flex justify-between items-start mb-3 pl-2">
                    <h3 className="font-bold text-gray-900 truncate pr-2">{node.name}</h3>
                    <Badge variant={online ? 'success' : 'error'}>
                      {online ? 'Online' : 'Offline'}
                    </Badge>
                  </div>
                  <div className="space-y-1.5 pl-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-500">Address</span>
                      <span className="font-mono text-gray-700 bg-gray-50 px-1.5 rounded">{node.addr}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500">Last Seen</span>
                      <span className="text-gray-700">{new Date(node.last_seen).toLocaleTimeString()}</span>
                    </div>
                    <div className="flex justify-between items-center pt-2 mt-2 border-t border-gray-100">
                      <span className="text-xs text-gray-400 font-mono">{node.id.substring(0, 12)}...</span>
                      {online ? <CheckCircle2 size={14} className="text-green-500" /> : <XCircle size={14} className="text-red-500" />}
                    </div>
                  </div>
                </Card>
              );
            })}
            {nodes.length === 0 && !loading && (
              <div className="col-span-full py-12 text-center bg-white rounded-xl border border-dashed border-gray-300 text-gray-500">
                No nodes registered yet. Start a server with <code className="bg-gray-100 px-1 rounded">-manager</code> flag.
              </div>
            )}
          </div>
        </section>

        {/* Tenants Section */}
        <section>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
            <h2 className="text-lg font-bold text-gray-800 flex items-center gap-2">
              <Users size={20} className="text-gray-400" />
              Tenants Management
            </h2>
            <div className="flex items-center gap-3 w-full sm:w-auto">
              <div className="relative flex-1 sm:w-64">
                <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                <input 
                  className="w-full pl-9 pr-4 py-2 bg-white border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                  placeholder="Search tenants..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
              <Button icon={UserPlus} onClick={() => setShowModal(true)}>
                Add Tenant
              </Button>
            </div>
          </div>

          <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-gray-50/50 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-4 font-semibold text-gray-500">ID</th>
                    <th className="px-6 py-4 font-semibold text-gray-500">Username</th>
                    <th className="px-6 py-4 font-semibold text-gray-500">Quota</th>
                    <th className="px-6 py-4 font-semibold text-gray-500">Subscription</th>
                    <th className="px-6 py-4 font-semibold text-gray-500">Created At</th>
                    <th className="px-6 py-4 font-semibold text-gray-500 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {filteredUsers.map((u) => (
                    <tr key={u.id} className="hover:bg-gray-50/50 transition-colors group">
                      <td className="px-6 py-4 text-gray-400 font-mono text-xs">#{u.id}</td>
                      <td className="px-6 py-4 font-medium text-gray-900">
                        <div className="flex items-center gap-2">
                          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-100 to-indigo-100 text-blue-600 flex items-center justify-center font-bold text-xs">
                            {u.username.substring(0, 2).toUpperCase()}
                          </div>
                          {u.username}
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <Badge variant="default">{(u.quota_bytes / 1024 / 1024 / 1024).toFixed(0)} GB</Badge>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2 max-w-[200px]">
                           <code className="text-xs bg-gray-50 px-2 py-1 rounded border border-gray-200 truncate flex-1 text-gray-500 select-all">
                             {getSubLink(u.token)}
                           </code>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-gray-500">
                        {new Date(u.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 text-right">
                         <button 
                           onClick={() => copyToClipboard(getSubLink(u.token))}
                           className="text-gray-400 hover:text-blue-600 p-1.5 hover:bg-blue-50 rounded-lg transition-colors"
                           title="Copy Link"
                         >
                           <Copy size={16} />
                         </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {filteredUsers.length === 0 && !loading && (
              <div className="p-12 text-center">
                <div className="bg-gray-50 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-3">
                  <Users size={24} className="text-gray-400" />
                </div>
                <h3 className="text-gray-900 font-medium">No tenants found</h3>
                <p className="text-gray-500 text-sm mt-1">Get started by creating a new tenant.</p>
              </div>
            )}
          </div>
        </section>
      </main>

      {/* Modal Backdrop */}
      {showModal && (
        <div className="fixed inset-0 bg-black/20 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
          <Card className="w-full max-w-md p-0 overflow-hidden shadow-2xl animate-in zoom-in-95 duration-200">
            <div className="px-6 py-4 border-b border-gray-100 bg-gray-50/50 flex justify-between items-center">
              <h3 className="font-bold text-gray-900">Add New Tenant</h3>
              <button onClick={() => setShowModal(false)} className="text-gray-400 hover:text-gray-600">
                <XCircle size={20} />
              </button>
            </div>
            
            <form onSubmit={handleCreate} className="p-6 space-y-4">
              <Input
                label="Username"
                placeholder="e.g. alice_corp"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoFocus
              />
              <Input
                label="Data Quota (GB)"
                type="number"
                placeholder="10"
                value={quota}
                onChange={(e) => setQuota(parseInt(e.target.value) || 0)}
                required
                min="1"
              />
              <Input
                label="Speed Limit (MB/s) - 0 for Unlimited"
                type="number"
                placeholder="0"
                value={bandwidth}
                onChange={(e) => setBandwidth(parseInt(e.target.value) || 0)}
                min="0"
              />
              
              <div className="flex justify-end gap-3 pt-2">
                <Button type="button" variant="secondary" onClick={() => setShowModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" isLoading={creating}>
                  Create Tenant
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}
    </div>
  );
}
