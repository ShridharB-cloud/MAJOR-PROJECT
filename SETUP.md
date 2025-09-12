# CYBY Security Scanner - Single Command Setup

## 🚀 Quick Start (One Command)

After setup, you can start both frontend and backend with a single command:

```bash
npm run start
```

## 📋 Setup Instructions

### Step 1: Install Node.js Dependencies
```bash
cd "C:\Users\LENOVO\OneDrive\Desktop\Major Project\cyber-scanner"
npm install
```

### Step 2: Install Python Dependencies
```bash
npm run setup
```

### Step 3: Start CYBY (Single Command)
```bash
npm run start
```

## 🎯 Available Commands

- `npm run start` - **Start both frontend and backend together**
- `npm run dev:all` - Alternative command to start both servers
- `npm run dev:frontend` - Start only frontend (React)
- `npm run dev:backend` - Start only backend (Python)
- `npm run dev` - Original frontend-only command

## 🖥️ Alternative Startup Methods

### Method 1: Batch File (Windows)
Double-click `start-cyby.bat` or run:
```bash
start-cyby.bat
```

### Method 2: PowerShell Script
```bash
.\start-cyby.ps1
```

## 🌐 Access CYBY

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000

## 📦 Added Dependencies

- **concurrently**: ^8.2.2 - Runs multiple commands simultaneously

## 🔧 What Was Modified

- **package.json**: Added new scripts and concurrently dependency
- **start-cyby.bat**: Windows batch file for easy startup
- **start-cyby.ps1**: PowerShell script for easy startup
- **No changes** to existing frontend or backend code

## ✅ Benefits

- ✅ Single command to start everything
- ✅ Color-coded terminal output
- ✅ Easy to stop both servers (Ctrl+C)
- ✅ No changes to existing code
- ✅ Works on Windows, Mac, and Linux
