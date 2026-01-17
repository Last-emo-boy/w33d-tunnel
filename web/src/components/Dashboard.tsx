import { useEffect, useState } from 'react';
import { listUsers, createUser, listNodes } from '../api';
import { Copy, RefreshCw, UserPlus, Server } from 'lucide-react';

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
  
  // New User Form
  const [username, setUsername] = useState('');
  const [quota, setQuota] = useState(10);
  const [showModal, setShowModal] = useState(false);

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
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await createUser(username, quota);
      setShowModal(false);
      setUsername('');
      fetchData();
    } catch (err) {
      alert('Failed to create user');
    }
  };

  const getSubLink = (token: string) => {
    const baseUrl = window.location.origin;
    return `${baseUrl}/api/subscribe?token=${token}`;
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    alert('Copied!');
  };
  
  const isOnline = (lastSeen: string) => {
    const diff = new Date().getTime() - new Date(lastSeen).getTime();
    return diff < 120000; // 2 minutes
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-6xl mx-auto">
        {/* Nodes Section */}
        <div className="mb-12">
          <div className="flex justify-between items-center mb-6">
            <h1 className="text-3xl font-bold flex items-center gap-2">
              <Server /> Tunnel Nodes
            </h1>
            <button onClick={fetchData} className="p-2 bg-gray-700 rounded hover:bg-gray-600">
              <RefreshCw size={20} />
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {nodes.map(node => (
              <div key={node.id} className="bg-gray-800 p-6 rounded-lg border border-gray-700">
                <div className="flex justify-between items-start mb-4">
                  <h3 className="text-xl font-bold">{node.name}</h3>
                  <span className={`px-2 py-1 rounded text-xs ${isOnline(node.last_seen) ? 'bg-green-900 text-green-300' : 'bg-red-900 text-red-300'}`}>
                    {isOnline(node.last_seen) ? 'Online' : 'Offline'}
                  </span>
                </div>
                <div className="space-y-2 text-gray-400 text-sm">
                  <p>ID: <span className="text-white">{node.id}</span></p>
                  <p>Addr: <span className="text-white">{node.addr}</span></p>
                  <p>Last Seen: {new Date(node.last_seen).toLocaleString()}</p>
                </div>
              </div>
            ))}
            {nodes.length === 0 && !loading && (
              <div className="text-gray-500 col-span-full text-center py-8 bg-gray-800 rounded">
                No nodes registered yet. Run a server with -manager flag.
              </div>
            )}
          </div>
        </div>

        {/* Users Section */}
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <UserPlus /> Tenants
          </h1>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 bg-green-600 px-4 py-2 rounded hover:bg-green-500"
          >
             Add Tenant
          </button>
        </div>

        <div className="bg-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-left">
            <thead className="bg-gray-700">
              <tr>
                <th className="p-4">ID</th>
                <th className="p-4">Username</th>
                <th className="p-4">Token</th>
                <th className="p-4">Subscription Link</th>
                <th className="p-4">Quota (GB)</th>
                <th className="p-4">Created</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b border-gray-700 hover:bg-gray-750">
                  <td className="p-4 text-gray-400">{u.id}</td>
                  <td className="p-4 font-bold">{u.username}</td>
                  <td className="p-4 font-mono text-sm text-gray-400">{u.token}</td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <input
                        readOnly
                        value={getSubLink(u.token)}
                        className="bg-gray-900 border border-gray-600 rounded px-2 py-1 text-sm w-64"
                      />
                      <button
                        onClick={() => copyToClipboard(getSubLink(u.token))}
                        className="p-1 hover:text-blue-400"
                      >
                        <Copy size={16} />
                      </button>
                    </div>
                  </td>
                  <td className="p-4">{(u.quota_bytes / 1024 / 1024 / 1024).toFixed(1)}</td>
                  <td className="p-4 text-sm text-gray-400">
                    {new Date(u.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {users.length === 0 && !loading && (
            <div className="p-8 text-center text-gray-500">No tenants found.</div>
          )}
        </div>
      </div>

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center">
          <div className="bg-gray-800 p-6 rounded-lg w-96">
            <h2 className="text-xl font-bold mb-4">Create New Tenant</h2>
            <form onSubmit={handleCreate} className="flex flex-col gap-4">
              <div>
                <label className="block text-sm mb-1">Username</label>
                <input
                  className="w-full p-2 rounded bg-gray-700 border border-gray-600"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                />
              </div>
              <div>
                <label className="block text-sm mb-1">Quota (GB)</label>
                <input
                  type="number"
                  className="w-full p-2 rounded bg-gray-700 border border-gray-600"
                  value={quota}
                  onChange={(e) => setQuota(parseInt(e.target.value))}
                  required
                />
              </div>
              <div className="flex justify-end gap-2 mt-4">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 text-gray-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-blue-600 rounded hover:bg-blue-500"
                >
                  Create
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
