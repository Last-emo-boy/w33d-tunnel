import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000/api';

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

export const createUser = async (username: string, quotaGB: number) => {
  const res = await api.post('/admin/users', { username, quota_gb: quotaGB });
  return res.data;
};

export default api;
