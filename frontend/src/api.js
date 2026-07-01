import axios from 'axios';

// Central API client for the SentinelIQ backend.
// Change BASE_URL here if the FastAPI server moves.
export const BASE_URL =
  process.env.REACT_APP_API_URL ||
  'http://localhost:8000';

// Sent on every request so the backend's protected endpoints accept it.
const SENTINELIQ_API_KEY =
  process.env.REACT_APP_SENTINELIQ_API_KEY || '';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 45000,
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': SENTINELIQ_API_KEY,
  },
});

export default api;

export const keepAlive = () => {
  const url = process.env.REACT_APP_API_URL ||
              'https://sentineliq-d0ot.onrender.com';
  setInterval(() => {
    fetch(`${url}/`)
      .catch(() => {});
  }, 4 * 60 * 1000);
};
