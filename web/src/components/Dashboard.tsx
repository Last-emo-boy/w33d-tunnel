import { useEffect, useState } from 'react';
import { listUsers, createUser } from '../api';
import { Copy, Plus, RefreshCw, UserPlus } from 'lucide-react';

interface User {
  id: number;
  username: string;
  token: string;
  created_at: string;
  quota_bytes: number;
}

export default function Dashboard() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);
  
  // New User Form
  const [username, setUsername] = useState('');
  const [quota, setQuota] = useState(10);
  const [showModal, setShowModal] = useState(false);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const data = await listUsers();
      setUsers(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await createUser(username, quota);
      setShowModal(false);
      setUsername('');
      fetchUsers();
    } catch (err) {
      alert('Failed to create user');
    }
  };

  const getSubLink = (token: string) => {
    // Assuming API is on same host/port in production (via Nginx)
    // Or configurable.
    const baseUrl = window.location.origin;
    return `${baseUrl}/api/subscribe?token=${token}`;
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    alert('Copied!');
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-6xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold">Tenant Management</h1>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 bg-green-600 px-4 py-2 rounded hover:bg-green-500"
          >
            <UserPlus size={20} /> Add Tenant
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
