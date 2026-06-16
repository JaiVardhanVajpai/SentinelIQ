import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Home from './pages/Home';
import Results from './pages/Results';
import History from './pages/History';
import Dashboard from './pages/Dashboard';
import ThreatHunt from './pages/ThreatHunt';
import BulkUpload from './pages/BulkUpload';
import Footer from './components/Footer';
import { keepAlive } from './api';

function App() {
  React.useEffect(() => {
    keepAlive();
  }, []);

  return (
    <Router>
      <div
        className="bg-gray-950 text-white"
        style={{
          display: 'flex',
          flexDirection: 'column',
          minHeight: '100vh'
        }}
      >
        <Navbar />
        <main style={{ flex: 1 }}>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/results" element={<Results />} />
            <Route path="/history" element={<History />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/hunt" element={<ThreatHunt />} />
            <Route path="/bulk" element={<BulkUpload />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </Router>
  );
}

export default App;
