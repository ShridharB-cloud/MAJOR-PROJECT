// API Configuration
export const API_BASE_URL = import.meta.env.MODE === 'production' 
  ? '' // Relative path for Vercel rewrites
  : 'http://localhost:5001' // Local backend URL

export const FRONTEND_URL = import.meta.env.MODE === 'production'
  ? window.location.origin // Deployed frontend URL
  : 'http://localhost:5000' // Local frontend URL
