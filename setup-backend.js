import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('📦 Installing Python dependencies for CYBY backend...');

const backendDir = path.join(__dirname, 'backend');
const pipProcess = spawn('pip', ['install', '-r', 'requirements.txt'], {
  cwd: backendDir,
  stdio: 'inherit',
  shell: true
});

pipProcess.on('error', (err) => {
  console.error('❌ Failed to install dependencies:', err.message);
  console.log('💡 Make sure Python and pip are installed');
});

pipProcess.on('close', (code) => {
  if (code === 0) {
    console.log('✅ Python dependencies installed successfully!');
    console.log('🚀 You can now run: npm run start');
  } else {
    console.log('❌ Failed to install dependencies');
  }
});
