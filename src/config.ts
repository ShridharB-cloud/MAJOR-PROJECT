// API Configuration
export const API_BASE_URL = process.env.NODE_ENV === 'production' 
  ? 'https://cyby-backend.onrender.com' // Deployed backend URL
  : 'http://localhost:5001' // Local backend URL

export const FRONTEND_URL = process.env.NODE_ENV === 'production'
  ? 'https://cyby-security-scanner.vercel.app' // Deployed frontend URL
  : 'http://localhost:5000' // Local frontend URL
