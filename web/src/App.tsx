import { useState } from 'react';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import { getAdminToken } from './api';

function App() {
  const [isAdmin, setIsAdmin] = useState(!!getAdminToken());

  return (
    <div>
      {isAdmin ? (
        <Dashboard />
      ) : (
        <Login onLogin={() => setIsAdmin(true)} />
      )}
    </div>
  );
}

export default App;
