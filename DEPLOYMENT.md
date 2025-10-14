# 🚀 CYBY Security Scanner - Deployment Guide

## 📋 Prerequisites

1. **GitHub Account** - For code repository
2. **Vercel Account** - For frontend deployment (free)
3. **Render Account** - For backend deployment (free)

## 🌐 Step 1: Deploy Frontend (Vercel)

### 1.1 Push to GitHub
```bash
git add .
git commit -m "Deploy CYBY Security Scanner"
git push origin main
```

### 1.2 Deploy on Vercel
1. Go to [vercel.com](https://vercel.com)
2. Sign up/Login with GitHub
3. Click "New Project"
4. Import your GitHub repository
5. Configure:
   - **Framework Preset**: Vite
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
6. Click "Deploy"

### 1.3 Get Frontend URL
- Vercel will provide: `https://your-project-name.vercel.app`
- Update `src/config.ts` with your Vercel URL

## 🔧 Step 2: Deploy Backend (Render)

### 2.1 Deploy on Render
1. Go to [render.com](https://render.com)
2. Sign up/Login with GitHub
3. Click "New +" → "Web Service"
4. Connect your GitHub repository
5. Configure:
   - **Name**: `cyby-backend`
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `cd backend && python main.py`
6. Click "Create Web Service"

### 2.2 Get Backend URL
- Render will provide: `https://cyby-backend.onrender.com`
- Update `src/config.ts` with your Render URL

## 🔄 Step 3: Update Configuration

Update `src/config.ts`:
```typescript
export const API_BASE_URL = process.env.NODE_ENV === 'production' 
  ? 'https://cyby-backend.onrender.com' // Your Render URL
  : 'http://localhost:5001'

export const FRONTEND_URL = process.env.NODE_ENV === 'production'
  ? 'https://your-project-name.vercel.app' // Your Vercel URL
  : 'http://localhost:5000'
```

## 📱 Step 4: Share Your App

### WhatsApp Sharing
1. Copy your Vercel URL: `https://your-project-name.vercel.app`
2. Share on WhatsApp (mobile or PC)
3. Anyone can open the link directly!

### Mobile Access
- The app is fully responsive
- Works on all devices
- No installation required

## ✅ Verification

### Test Your Deployment
1. **Frontend**: Visit your Vercel URL
2. **Backend**: Visit `https://your-backend-url.onrender.com/health`
3. **Full App**: Run a security scan on your deployed app

### Expected Results
- ✅ Frontend loads at Vercel URL
- ✅ Backend responds at Render URL
- ✅ Security scans work properly
- ✅ PDF generation works
- ✅ Mobile access works

## 🛠️ Troubleshooting

### Common Issues
1. **CORS Errors**: Update backend CORS settings
2. **Build Failures**: Check Node.js/Python versions
3. **API Errors**: Verify backend URL in config

### Support
- Check Vercel/Render logs for errors
- Verify environment variables
- Test locally first

## 🎉 Success!

Your CYBY Security Scanner is now live and shareable!

**Share this link**: `https://your-project-name.vercel.app`

---

**CYBY Security Scanner** - Professional security testing made simple.
