# CYBY Security Scanner 🔒

An AI-powered web vulnerability scanner built with React frontend and Python FastAPI backend.

## 🌟 Features

- **AI-Based Scanning**: Advanced vulnerability detection with 80%+ accuracy
- **Multiple Vulnerability Types**: SQL Injection, XSS, CSRF, Security Headers, and more
- **Professional PDF Reports**: Generate detailed security reports
- **Modern UI**: Clean, professional interface with Poppins/Roboto fonts
- **Real-time Progress**: Live scanning progress with visual feedback
- **Cross-platform**: Works on Windows, Mac, and Linux

## 🚀 Quick Start

### Prerequisites
- Node.js (v16 or higher)
- Python (v3.8 or higher)
- Git

### Installation & Setup

1. **Clone the repository**
   ```bash
   git clone <your-repository-url>
   cd cyber-scanner
   ```

2. **Install Node.js dependencies**
   ```bash
   npm install
   ```

3. **Install Python dependencies**
   ```bash
   npm run setup
   ```

4. **Start CYBY**
   ```bash
   npm run start
   ```

5. **Access the application**
   - Frontend: http://localhost:5173
   - Backend API: http://localhost:8000

## 📋 Available Commands

| Command | Description |
|---------|-------------|
| `npm run start` | Start both frontend and backend |
| `npm run setup` | Install Python dependencies |
| `npm run dev:frontend` | Start frontend only |
| `npm run dev:backend` | Start backend only |
| `npm run build` | Build for production |

## 🛠️ Alternative Startup Methods

### Method 1: Batch File (Windows)
Double-click `start-cyby.bat` or `restart-cyby.bat`

### Method 2: Manual Commands
```bash
# Navigate to project directory
cd "path/to/cyber-scanner"

# Start both servers
npm run start
```

## 🔧 Troubleshooting

### Port Conflicts
If you get port conflicts, use the restart script:
```bash
restart-cyby.bat
```

### Backend Connection Issues
1. Make sure Python dependencies are installed: `npm run setup`
2. Check if port 8000 is available
3. Restart the application

### Frontend Issues
1. Clear browser cache
2. Try different port (5174 if 5173 is busy)
3. Restart the development server

## 📁 Project Structure

```
cyber-scanner/
├── src/                    # React frontend
│   ├── App.tsx            # Main application component
│   ├── App.css            # Application styles
│   └── index.css           # Global styles
├── backend/               # Python FastAPI backend
│   ├── main.py            # Main server file
│   └── requirements.txt   # Python dependencies
├── package.json           # Node.js dependencies
├── start-cyby.bat         # Windows startup script
├── restart-cyby.bat       # Windows restart script
└── README.md              # This file
```

## 🎯 Vulnerability Types Scanned

- **SQL Injection**: Database query vulnerabilities
- **Cross-Site Scripting (XSS)**: Script injection attacks
- **Cross-Site Request Forgery (CSRF)**: Unauthorized actions
- **Security Headers**: Missing security configurations
- **Directory Traversal**: File system access vulnerabilities
- **File Upload**: Unsafe file handling
- **Authentication Bypass**: Login mechanism flaws
- **Session Management**: Session security issues
- **Rate Limiting**: DoS protection
- **SSL/TLS**: Encryption vulnerabilities

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Commit your changes: `git commit -m "Add feature"`
5. Push to the branch: `git push origin feature-name`
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 👥 Authors

- **Your Name** - Initial work
- **Your Friend** - Collaborator

## 🆘 Support

If you encounter any issues:
1. Check the troubleshooting section
2. Create an issue on GitHub
3. Contact the maintainers

---

**CYBY Security Scanner** - Making web security accessible to everyone! 🛡️