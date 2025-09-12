// API Configuration
export const API_BASE_URL = process.env.NODE_ENV === 'production' 
  ? 'https://cyber-scanner-backend.railway.app' // Replace with your deployed backend URL
  : 'http://192.168.79.180:8000' // Use your computer's IP for mobile access

export const FRONTEND_URL = process.env.NODE_ENV === 'production'
  ? 'https://cyber-scanner.vercel.app' // Replace with your deployed frontend URL
  : 'http://localhost:5173'
