import axios from 'axios';

// Central API client for the SentinelIQ backend.
// Change BASE_URL here if the FastAPI server moves.
export const BASE_URL = 'http://localhost:8000';

const api = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
});

export default api;
