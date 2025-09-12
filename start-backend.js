import { spawn, exec } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🚀 Starting CYBY Backend...');

// Kill any existing processes on port 8000
console.log('🔧 Checking for existing processes on port 8000...');
exec('netstat -ano | findstr :8000', (error, stdout) => {
  if (stdout) {
    const lines = stdout.trim().split('\n');
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 5) {
        const pid = parts[4];
        console.log(`🛑 Killing existing process PID: ${pid}`);
        exec(`taskkill /PID ${pid} /F`, (killError) => {
          if (killError) {
            console.log('⚠️ Could not kill process, continuing...');
          }
        });
      }
    }
  }
  
  // Wait a moment then start the backend
  setTimeout(() => {
    startBackend();
  }, 2000);
});

function startBackend() {
  console.log('🚀 Starting backend server...');
  
  // Change to backend directory and start Python server
  const backendDir = path.join(__dirname, 'backend');
  const pythonProcess = spawn('python', ['main.py'], {
    cwd: backendDir,
    stdio: 'inherit',
    shell: true
  });

  pythonProcess.on('error', (err) => {
    console.error('❌ Failed to start backend:', err.message);
    console.log('💡 Make sure Python is installed and dependencies are installed:');
    console.log('   cd backend && pip install -r requirements.txt');
  });

  pythonProcess.on('close', (code) => {
    console.log(`🔴 Backend process exited with code ${code}`);
  });

  // Handle process termination
  process.on('SIGINT', () => {
    console.log('\n🛑 Stopping backend...');
    pythonProcess.kill();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    console.log('\n🛑 Stopping backend...');
    pythonProcess.kill();
    process.exit(0);
  });
}
