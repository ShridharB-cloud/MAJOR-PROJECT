# Backend Deployment Guide

## Deploy to Render

1. **Create a Render Account**
   - Go to [render.com](https://render.com)
   - Sign up or log in with your GitHub account

2. **Create a New Web Service**
   - Click "New +" → "Web Service"
   - Connect your GitHub repository: `ShridharB-cloud/MAJOR-PROJECT`
   - Render will automatically detect the `render.yaml` file

3. **Configure the Service**
   - The `render.yaml` file already contains all necessary configuration
   - Service name: `cyby-backend`
   - Environment: Python
   - Build Command: `pip install -r backend/requirements.txt`
   - Start Command: `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT`

4. **Deploy**
   - Click "Create Web Service"
   - Render will automatically deploy your backend
   - Your backend URL will be: `https://cyby-backend.onrender.com`

5. **Verify Deployment**
   - Once deployed, visit: `https://cyby-backend.onrender.com/docs`
   - You should see the FastAPI Swagger documentation

## Frontend Configuration

The frontend is already configured to use the deployed backend:
- Production: `https://cyby-backend.onrender.com`
- Development: `http://localhost:5001`

This is set in `src/config.ts`

## Important Notes

- Render free tier may have cold starts (first request takes longer)
- The backend will sleep after 15 minutes of inactivity
- First request after sleep will take 30-60 seconds to wake up

## Testing

After deployment, test the connection:
1. Go to your Vercel frontend: `https://cyby-security-scanner.vercel.app`
2. Navigate to the Scanner page
3. Enter a test URL and run a scan
4. The scanner should connect to the Render backend automatically
