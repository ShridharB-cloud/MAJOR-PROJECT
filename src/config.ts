// API Configuration
export const API_BASE_URL = import.meta.env.PROD
  ? 'https://cyby-backend.onrender.com' // Deployed backend URL
  : 'http://localhost:5001' // Local backend URL

export const FRONTEND_URL = import.meta.env.PROD
  ? 'https://cyby-security-scanner.vercel.app' // Deployed frontend URL
  : 'http://localhost:5000' // Local frontend URL
