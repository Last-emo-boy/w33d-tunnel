import { useState } from 'react';
import { adminLogin } from '../api';
import { Card } from './ui/Card';
import { Input } from './ui/Input';
import { Button } from './ui/Button';
import { Shield, Lock, ArrowRight } from 'lucide-react';

interface LoginProps {
  onLogin: () => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await adminLogin(token);
      onLogin();
    } catch (err) {
      setError('Invalid Access Token');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-50 p-4">
      <div className="mb-8 text-center">
        <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-blue-600 text-white shadow-lg shadow-blue-600/20 mb-4">
          <Shield size={24} />
        </div>
        <h1 className="text-2xl font-bold text-gray-900 tracking-tight">w33d <span className="text-blue-600">Tunnel</span></h1>
        <p className="text-gray-500 text-sm mt-1">Admin Dashboard Access</p>
      </div>

      <Card className="w-full max-w-sm">
        <form onSubmit={handleSubmit} className="flex flex-col gap-6">
          <Input
            label="Admin Token"
            type="password"
            placeholder="Enter your secret token"
            icon={Lock}
            value={token}
            onChange={(e) => {
              setToken(e.target.value);
              setError('');
            }}
            autoFocus
          />
          
          {error && (
            <div className="p-3 bg-red-50 text-red-600 text-sm rounded-lg border border-red-100 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
              {error}
            </div>
          )}

          <Button type="submit" isLoading={loading} className="w-full group">
            Login to Dashboard
            <ArrowRight size={16} className="group-hover:translate-x-1 transition-transform" />
          </Button>
        </form>
      </Card>
      
      <p className="mt-8 text-xs text-gray-400">
        &copy; {new Date().getFullYear()} w33d Tunnel. Secure & Fast.
      </p>
    </div>
  );
}
