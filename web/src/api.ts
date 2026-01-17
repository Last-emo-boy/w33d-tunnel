import axios from 'axios';

// Use relative path to allow Nginx to proxy it correctly on any port
const API_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_URL,
});

export const setAdminToken = (token: string) => {
  api.defaults.headers.common['X-Admin-Token'] = token;
  localStorage.setItem('adminToken', token);
};

export const getAdminToken = () => localStorage.getItem('adminToken');

if (getAdminToken()) {
  setAdminToken(getAdminToken()!);
}

export const adminLogin = async (token: string) => {
  await api.post('/admin/login', { token });
  setAdminToken(token);
};

export const listUsers = async () => {
  const res = await api.get('/admin/users');
  return res.data;
};

export const createUser = async (username: string, quotaGB: number, bandwidthLimit: number) => {
  const res = await api.post('/admin/users', { 
    username, 
    quota_gb: quotaGB,
    bandwidth_limit: bandwidthLimit // Bytes/s
  });
  return res.data;
};

export const updateUser = async (token: string, quotaGB: number, bandwidthLimit: number) => {
  const res = await api.put('/admin/users', { 
    token, 
    quota_gb: quotaGB,
    bandwidth_limit: bandwidthLimit 
  });
  return res.data;
};

export const deleteUser = async (token: string) => {
  const res = await api.delete(`/admin/users?token=${token}`);
  return res.data;
};

export const listNodes = async () => {
  const res = await api.get('/nodes');
  return res.data;
};

export default api;
