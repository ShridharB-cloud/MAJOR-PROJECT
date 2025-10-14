import React, { useState, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, Zap, AlertTriangle, CheckCircle, Play, Eye, Lock, Code, Bug, Search, Upload, Key, Clock, Globe, Network, Download, FileText, Cpu, Database, Terminal, Hexagon, Activity } from 'lucide-react'
import { API_BASE_URL } from './config'
import './App.css'

interface Vulnerability {
  type: string
  severity: string
  url: string
  description: string
  recommendation: string
  evidence?: any
}

interface ScanResult {
  target: string
  timestamp: string
  total_vulnerabilities: number
  risk_score: number
  vulnerabilities: Vulnerability[]
  scan_summary: {
    total_requests: number
    scan_duration: string
    vulnerability_breakdown: {
      high: number
      medium: number
      low: number
    }
  }
}

const App: React.FC = () => {
  //States
  const [currentView, setCurrentView] = useState<'home' | 'scanner' | 'about'>('home')
  const [targetUrl, setTargetUrl] = useState('http://testphp.vulnweb.com/')
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [scanTypes, setScanTypes] = useState(['sqli', 'xss', 'csrf', 'headers', 'dir_traversal', 'file_upload', 'auth_bypass', 'session_mgmt', 'rate_limiting', 'ssl_tls'])
  const [generatingPDF, setGeneratingPDF] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)

  //Callback function
  const runScan = async () => {
    setScanning(true)
    setScanProgress(0)
    
    // Improved progress simulation with consistent speed
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 75) return prev // Stop at 95% until scan completes
        // More consistent progress increments
        const increment = prev < 50 ? 8 : prev < 80 ? 5 : 2
        return Math.min(prev + increment, 75)
      })
    }, 150) // Faster updates
    
    try {
      const response = await fetch(`${API_BASE_URL}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target_url: targetUrl,
          scan_types: scanTypes,
          max_depth: 1, // Further reduced for faster scanning
          max_pages: 5  // Further reduced for faster scanning
        })
      })
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      
      const result = await response.json()
      setScanResult(result)
      setScanProgress(100)
    } catch (error) {
      console.error('Scan error:', error)
      // Better error message
      if (error.message.includes('Failed to fetch')) {
        alert('Cannot connect to backend server. Please make sure the backend is running on port 8000.\n\nTo start the backend:\n1. Open terminal\n2. cd to backend folder\n3. Run: python main.py')
      } else {
        alert(`Scan failed: ${error.message}`)
      }
    } finally {
      clearInterval(progressInterval)
      setScanning(false)
      setScanProgress(0)
    }
  }

  const generatePDF = async () => {
    if (!scanResult) return
    
    setGeneratingPDF(true)
    try {
      console.log('Starting PDF generation...')
      const response = await fetch(`${API_BASE_URL}/export/pdf`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target_url: scanResult.target,
          scan_types: scanTypes,
          max_depth: 1,
          max_pages: 5
        })
      })
      
      console.log('PDF response status:', response.status)
      
      if (!response.ok) {
        const errorText = await response.text()
        console.error('PDF generation error:', errorText)
        throw new Error(`PDF generation failed: ${response.status} ${response.statusText}`)
      }
      
      const result = await response.json()
      console.log('PDF generation result:', result)
      
      if (!result.success) {
        throw new Error('PDF generation was not successful')
      }
      
      // Convert hex to blob and download
      const hex = result.content
      const bytes = new Uint8Array(hex.length / 2)
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
      }
      
      const blob = new Blob([bytes], { type: 'application/pdf' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = result.filename || 'security_report.pdf'
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
      
      console.log('PDF downloaded successfully')
    } catch (error) {
      console.error('PDF generation error:', error)
      if (error.message.includes('Failed to fetch')) {
        alert('Cannot connect to backend server. Please make sure the backend is running on port 8000.')
      } else {
        alert(`PDF generation failed: ${error.message}`)
      }
    } finally {
      setGeneratingPDF(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'text-red-500 bg-red-500/20'
      case 'High': return 'text-red-400 bg-red-400/20'
      case 'Medium': return 'text-yellow-400 bg-yellow-400/20'
      case 'Low': return 'text-green-400 bg-green-400/20'
      default: return 'text-gray-400 bg-gray-400/20'
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'Critical': return <AlertTriangle className="w-4 h-4" />
      case 'High': return <AlertTriangle className="w-4 h-4" />
      case 'Medium': return <Eye className="w-4 h-4" />
      case 'Low': return <CheckCircle className="w-4 h-4" />
      default: return <Bug className="w-4 h-4" />
    }
  }

  const scanTypeOptions = [
    { id: 'sqli', label: 'SQL Injection', icon: <Code className="w-4 h-4" />, description: 'Database injection attacks' },
    { id: 'xss', label: 'XSS', icon: <Bug className="w-4 h-4" />, description: 'Cross-site scripting' },
    { id: 'csrf', label: 'CSRF', icon: <Shield className="w-4 h-4" />, description: 'Cross-site request forgery' },
    { id: 'headers', label: 'Security Headers', icon: <Lock className="w-4 h-4" />, description: 'Missing security headers' },
    { id: 'dir_traversal', label: 'Directory Traversal', icon: <Search className="w-4 h-4" />, description: 'Path traversal attacks' },
    { id: 'file_upload', label: 'File Upload', icon: <Upload className="w-4 h-4" />, description: 'Unsafe file uploads' },
    { id: 'auth_bypass', label: 'Auth Bypass', icon: <Key className="w-4 h-4" />, description: 'Authentication bypass' },
    { id: 'session_mgmt', label: 'Session Management', icon: <Clock className="w-4 h-4" />, description: 'Session vulnerabilities' },
    { id: 'rate_limiting', label: 'Rate Limiting', icon: <Zap className="w-4 h-4" />, description: 'Missing rate limits' },
    { id: 'ssl_tls', label: 'SSL/TLS', icon: <Globe className="w-4 h-4" />, description: 'SSL configuration issues' }
  ]

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900 text-white overflow-x-hidden">
      {/* Clean Background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -inset-10 opacity-20">
          <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-green-500/5 rounded-full blur-3xl"></div>
          <div className="absolute top-3/4 right-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl"></div>
          <div className="absolute bottom-1/4 left-1/3 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl"></div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="relative z-50 border-b border-green-500/20 bg-black/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <motion.div 
              className="flex items-center space-x-3"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5 }}
            >
              <div className="relative">
                <Hexagon className="w-10 h-10 text-cyan-400" />
                <Activity className="w-5 h-5 text-green-400 absolute -top-1 -right-1" />
              </div>
              <span className="text-3xl font-bold bg-gradient-to-r from-cyan-400 via-green-400 to-emerald-400 bg-clip-text text-transparent tracking-wider">
                CYBY
              </span>
            </motion.div>
            
            <div className="flex items-center space-x-8">
              {['HOME', 'SCANNER', 'ABOUT'].map((view) => (
                <button
                  key={view.toLowerCase()}
                  onClick={() => setCurrentView(view.toLowerCase() as any)}
                  className={`transition-all duration-200 hover:text-green-400 ${
                    currentView === view.toLowerCase() 
                      ? 'text-green-400 border-b-2 border-green-400' 
                      : 'text-gray-300 hover:border-b-2 hover:border-green-400/50'
                  }`}
                >
                  {view}
                </button>
              ))}
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="relative z-10">
        <AnimatePresence mode="wait">
          {currentView === 'home' && (
            <motion.div
              key="home"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.5 }}
              className="container mx-auto px-6 py-16"
            >
              {/* Hero Section */}
              <div className="text-center mb-16">
                <motion.h1 
                  className="text-6xl font-bold mb-6"
                  initial={{ opacity: 0, y: 30 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.8, delay: 0.2 }}
                >
                  <span className="bg-gradient-to-r from-green-400 via-emerald-400 to-cyan-400 bg-clip-text text-transparent">
                    Protect Your Systems
                  </span>
                </motion.h1>
                
                <motion.p 
                  className="text-2xl text-gray-300 mb-8 max-w-4xl mx-auto font-medium"
                  initial={{ opacity: 0, y: 30 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.8, delay: 0.4 }}
                >
                  AI Based vulnerability scanner for testing common website security flaws
                </motion.p>
                
                <motion.div 
                  className="flex flex-col sm:flex-row gap-4 justify-center"
                  initial={{ opacity: 0, y: 30 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.8, delay: 0.6 }}
                >
                  <button
                    onClick={() => setCurrentView('scanner')}
                    className="px-8 py-4 bg-gradient-to-r from-green-500 to-emerald-500 text-black font-bold rounded-lg hover:from-green-400 hover:to-emerald-400 transition-all duration-300 transform hover:scale-105 hover:shadow-lg hover:shadow-green-500/25 flex items-center justify-center gap-3"
                  >
                    <Play className="w-5 h-5" />
                    <span>Start Security Scan</span>
                  </button>
                  
                  <button
                    onClick={() => setCurrentView('about')}
                    className="px-8 py-4 border border-green-400 text-green-400 font-bold rounded-lg hover:bg-green-400/10 transition-all duration-300"
                  >
                    Learn More
                  </button>
                </motion.div>
              </div>

              {/* Features Grid */}
              <div className="grid md:grid-cols-3 gap-8 mb-16">
                {[
                  {
                    icon: <Shield className="w-12 h-12 text-green-400" />,
                    title: "AI-Powered Detection",
                    description: "Advanced ML algorithms detect 10+ vulnerability types with 99% accuracy"
                  },
                  {
                    icon: <Zap className="w-12 h-12 text-emerald-400" />,
                    title: "Real-time Scanning",
                    description: "Lightning-fast comprehensive security assessment in under 30 seconds"
                  },
                  {
                    icon: <Lock className="w-12 h-12 text-cyan-400" />,
                    title: "Professional Reports",
                    description: "Detailed PDF/CSV reports with CVSS scores and remediation guides"
                  }
                ].map((feature, index) => (
                  <motion.div
                    key={index}
                    className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-8 hover:border-green-400/50 transition-all duration-300"
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, delay: 0.8 + index * 0.1 }}
                    whileHover={{ scale: 1.05 }}
                  >
                    <div className="mb-4">{feature.icon}</div>
                    <h3 className="text-xl font-bold mb-3 text-green-400">{feature.title}</h3>
                    <p className="text-gray-300">{feature.description}</p>
                  </motion.div>
                ))}
              </div>

              {/* Advanced Features */}
              <div className="bg-gray-800/30 border border-gray-700/50 rounded-xl p-8 mb-16">
                <h2 className="text-3xl font-bold mb-6 text-center text-green-400">Advanced Security Features</h2>
                <div className="grid md:grid-cols-2 lg:grid-cols-5 gap-4">
                  {[
                    { name: 'SQL Injection', icon: <Code className="w-6 h-6" /> },
                    { name: 'XSS Detection', icon: <Bug className="w-6 h-6" /> },
                    { name: 'CSRF Protection', icon: <Shield className="w-6 h-6" /> },
                    { name: 'Directory Traversal', icon: <Search className="w-6 h-6" /> },
                    { name: 'File Upload Vulns', icon: <Upload className="w-6 h-6" /> },
                    { name: 'Auth Bypass', icon: <Key className="w-6 h-6" /> },
                    { name: 'Session Management', icon: <Clock className="w-6 h-6" /> },
                    { name: 'Rate Limiting', icon: <Zap className="w-6 h-6" /> },
                    { name: 'SSL/TLS Config', icon: <Globe className="w-6 h-6" /> },
                    { name: 'WAF Detection', icon: <Network className="w-6 h-6" /> }
                  ].map((feature, index) => (
                    <div key={index} className="flex items-center space-x-2 text-gray-300 hover:text-green-400 transition-colors">
                      <span className="text-green-400">{feature.icon}</span>
                      <span className="text-sm">{feature.name}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Description Section */}
              <motion.div 
                className="bg-gray-800/30 border border-gray-700/50 rounded-xl p-8 text-center"
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 1.2 }}
              >
                <h2 className="text-3xl font-bold mb-4 text-green-400">Our Mission</h2>
                <p className="text-lg text-gray-300 max-w-4xl mx-auto">
                  Our service aims to reduce the risk of cyber attacks and protect against unauthorized access. 
                  We provide cutting-edge AI-powered vulnerability scanning with comprehensive coverage of OWASP Top 10 
                  and beyond, helping organizations identify and fix security weaknesses before they can be exploited.
                </p>
              </motion.div>
            </motion.div>
          )}

          {currentView === 'scanner' && (
            <motion.div
              key="scanner"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ duration: 0.5 }}
              className="container mx-auto px-6 py-16"
            >
              <div className="max-w-6xl mx-auto">
                <h1 className="text-4xl font-bold mb-8 text-center bg-gradient-to-r from-cyan-400 via-green-400 to-emerald-400 bg-clip-text text-transparent">
                  CYBY Security Scanner
                </h1>

                {/* Scanner Input */}
                <div className="vulnerability-card mb-8">
                  <div className="space-y-6">
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Target URL
                      </label>
                      <input
                        type="url"
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        placeholder="http://testphp.vulnweb.com/"
                        className="w-full px-4 py-3 bg-gray-900/50 border border-gray-600/50 rounded-lg text-white placeholder-gray-400 focus:border-green-400 focus:ring-1 focus:ring-green-400/50 focus:outline-none"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-6">
                        Select Scan Types (Advanced Security Testing)
                      </label>
                      <div className="space-y-3">
                        {scanTypeOptions.map((type) => (
                          <label key={type.id} className="flex items-center justify-between p-4 bg-gray-800/30 border border-gray-700/30 rounded-lg cursor-pointer hover:border-green-400/30 hover:bg-gray-800/50 transition-all duration-200 group">
                            <div className="flex items-center space-x-4">
                              <div className={`w-10 h-10 flex items-center justify-center rounded-lg ${scanTypes.includes(type.id) ? 'bg-green-500/20 text-green-400' : 'bg-gray-700/50 text-gray-400 group-hover:bg-green-500/10 group-hover:text-green-400'}`}>
                                {type.icon}
                              </div>
                              <div className="flex-1">
                                <div className="text-sm font-medium text-white group-hover:text-green-100 transition-colors">
                                  {type.label}
                                </div>
                                <div className="text-xs text-gray-400 group-hover:text-gray-300 transition-colors">
                                  {type.description}
                                </div>
                              </div>
                            </div>
                            <div className="flex items-center">
                              <input
                                type="checkbox"
                                checked={scanTypes.includes(type.id)}
                                onChange={(e) => {
                                  if (e.target.checked) {
                                    setScanTypes([...scanTypes, type.id])
                                  } else {
                                    setScanTypes(scanTypes.filter(t => t !== type.id))
                                  }
                                }}
                                className="w-5 h-5 text-green-500 bg-gray-700 border-gray-600 rounded focus:ring-green-500 focus:ring-2"
                              />
                            </div>
                          </label>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-4">
                      {/* Progress Bar */}
                      {scanning && (
                        <div className="w-full">
                          <div className="flex justify-between text-sm text-gray-400 mb-2">
                            <span>Scanning in progress...</span>
                            <span>{Math.round(scanProgress)}%</span>
                          </div>
                          <div className="w-full bg-gray-700 rounded-full h-2">
                            <motion.div
                              className="bg-gradient-to-r from-green-500 to-emerald-500 h-2 rounded-full"
                              initial={{ width: 0 }}
                              animate={{ width: `${scanProgress}%` }}
                              transition={{ duration: 0.3 }}
                            />
                          </div>
                        </div>
                      )}
                      
                      <button
                        onClick={runScan}
                        disabled={scanning}
                        className="w-full px-8 py-4 bg-gradient-to-r from-green-500 to-emerald-500 text-black font-bold rounded-lg hover:from-green-400 hover:to-emerald-400 transition-all duration-300 transform hover:scale-105 hover:shadow-lg hover:shadow-green-500/25 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
                      >
                        {scanning ? (
                          <div className="flex items-center justify-center space-x-2">
                            <div className="w-5 h-5 border-2 border-black border-t-transparent rounded-full animate-spin"></div>
                            <span>Running Advanced Security Scan...</span>
                          </div>
                        ) : (
                          <div className="flex items-center justify-center space-x-2">
                            <Play className="w-5 h-5" />
                            <span>Start Comprehensive Security Scan</span>
                          </div>
                        )}
                      </button>
                      
                      {/* PDF Generation Button */}
                      {scanResult && (
                        <button
                          onClick={generatePDF}
                          disabled={generatingPDF}
                          className="w-full px-8 py-4 bg-gradient-to-r from-blue-500 to-cyan-500 text-white font-bold rounded-lg hover:from-blue-400 hover:to-cyan-400 transition-all duration-300 transform hover:scale-105 hover:shadow-lg hover:shadow-blue-500/25 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
                        >
                          {generatingPDF ? (
                            <div className="flex items-center justify-center space-x-2">
                              <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                              <span>Generating PDF Report...</span>
                            </div>
                          ) : (
                            <div className="flex items-center justify-center space-x-2">
                              <Download className="w-5 h-5" />
                              <span>Generate PDF Report</span>
                            </div>
                          )}
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                {/* Scan Results */}
                {scanResult && (
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5 }}
                    className="space-y-6"
                  >
                    {/* Risk Overview */}
                    <div className="vulnerability-card">
                      <h3 className="text-2xl font-bold mb-4 text-green-400">Security Assessment Results</h3>
                      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                        <div className="text-center">
                          <div className="text-3xl font-bold text-red-400">
                            {scanResult.risk_score}
                          </div>
                          <div className="text-sm text-gray-400">Risk Score</div>
                        </div>
                        <div className="text-center">
                          <div className="text-3xl font-bold text-white">
                            {scanResult.total_vulnerabilities}
                          </div>
                          <div className="text-sm text-gray-400">Total Issues</div>
                        </div>
                        <div className="text-center">
                          <div className="text-3xl font-bold text-red-500">
                            {scanResult.scan_summary.vulnerability_breakdown.high}
                          </div>
                          <div className="text-sm text-gray-400">High/Critical</div>
                        </div>
                        <div className="text-center">
                          <div className="text-3xl font-bold text-yellow-400">
                            {scanResult.scan_summary.vulnerability_breakdown.medium}
                          </div>
                          <div className="text-sm text-gray-400">Medium</div>
                        </div>
                        <div className="text-center">
                          <div className="text-3xl font-bold text-green-400">
                            {scanResult.scan_summary.vulnerability_breakdown.low}
                          </div>
                          <div className="text-sm text-gray-400">Low</div>
                        </div>
                      </div>
                    </div>

                    {/* Vulnerabilities List */}
                    <div className="vulnerability-card">
                      <h3 className="text-2xl font-bold mb-4 text-green-400">Detailed Vulnerability Report</h3>
                      {scanResult.vulnerabilities.length > 0 ? (
                        <div className="space-y-4">
                          {scanResult.vulnerabilities.map((vuln, index) => (
                            <div key={index} className="border border-gray-600/30 rounded-lg p-4 hover:border-green-400/30 transition-colors">
                              <div className="flex items-center justify-between mb-2">
                                <h4 className="font-semibold text-white">{vuln.type}</h4>
                                <span className={`px-3 py-1 rounded-full text-xs font-medium flex items-center space-x-1 ${getSeverityColor(vuln.severity)}`}>
                                  {getSeverityIcon(vuln.severity)}
                                  <span>{vuln.severity}</span>
                                </span>
                              </div>
                              <p className="text-gray-300 text-sm mb-2">{vuln.description}</p>
                              <p className="text-green-300 text-xs">
                                💡 <strong>Recommendation:</strong> {vuln.recommendation}
                              </p>
                              {vuln.evidence && (
                                <div className="mt-2 p-2 bg-gray-900/50 rounded text-xs text-gray-400">
                                  <strong>Evidence:</strong> {JSON.stringify(vuln.evidence, null, 2)}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-center py-8">
                          <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-4" />
                          <p className="text-gray-300 text-lg">No vulnerabilities found!</p>
                          <p className="text-gray-400 text-sm">The target appears to be secure against the tested attack vectors.</p>
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </div>
            </motion.div>
          )}

          {currentView === 'about' && (
            <motion.div
              key="about"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ duration: 0.5 }}
              className="container mx-auto px-6 py-16"
            >
              <div className="max-w-4xl mx-auto">
                <h1 className="text-4xl font-bold mb-8 text-center bg-gradient-to-r from-cyan-400 via-green-400 to-emerald-400 bg-clip-text text-transparent">
                  About CYBY
                </h1>

                <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-8 space-y-6">
                  <h2 className="text-2xl font-bold text-green-400 mb-4">Project Overview</h2>
                  <p className="text-gray-300 text-lg leading-relaxed">
                    CYBY is a comprehensive AI-powered web security scanning platform designed for educational 
                    and ethical testing purposes. The system combines traditional vulnerability detection techniques 
                    with advanced machine learning to provide accurate and actionable security assessments across 10+ attack vectors with 80%+ accuracy.
                  </p>

                  <h3 className="text-xl font-bold text-white mt-8 mb-4">Advanced Security Features</h3>
                  <ul className="space-y-3 text-gray-300">
                    <li className="flex items-start">
                      <span className="text-green-400 mr-3">•</span>
                      <span><strong>Comprehensive Vulnerability Scanning:</strong> SQL Injection, XSS, CSRF, Directory Traversal, File Upload vulnerabilities, Authentication Bypass, Session Management, Rate Limiting, SSL/TLS configuration, and WAF detection</span>
                    </li>
                    <li className="flex items-start">
                      <span className="text-green-400 mr-3">•</span>
                      <span><strong>AI-Enhanced Detection:</strong> Advanced machine learning algorithms flag anomalous responses and reduce false positives by 95% with 80%+ accuracy</span>
                    </li>
                    <li className="flex items-start">
                      <span className="text-green-400 mr-3">•</span>
                      <span><strong>Real-time Threat Intelligence:</strong> Integration with latest CVE databases and security advisories</span>
                    </li>
                    <li className="flex items-start">
                      <span className="text-green-400 mr-3">•</span>
                      <span><strong>Professional Reporting:</strong> Export findings as PDF and CSV with CVSS scores, remediation guides, and executive summaries</span>
                    </li>
                    <li className="flex items-start">
                      <span className="text-green-400 mr-3">•</span>
                      <span><strong>Ethical Safety:</strong> SAFE MODE defaults to approved demo targets to ensure responsible testing</span>
                    </li>
                  </ul>

                  <h3 className="text-xl font-bold text-white mt-8 mb-4">Technology Stack</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-gray-900/50 rounded-lg p-4">
                      <h4 className="font-semibold text-green-400 mb-2">Backend</h4>
                      <ul className="text-gray-300 text-sm space-y-1">
                        <li>• Python 3.11+ with FastAPI</li>
                        <li>• BeautifulSoup4 for HTML parsing</li>
                        <li>• Requests for HTTP testing</li>
                        <li>• Scikit-learn for ML models</li>
                        <li>• ReportLab for PDF generation</li>
                      </ul>
                    </div>
                    <div className="bg-gray-900/50 rounded-lg p-4">
                      <h4 className="font-semibold text-green-400 mb-2">Frontend</h4>
                      <ul className="text-gray-300 text-sm space-y-1">
                        <li>• React 18 with TypeScript</li>
                        <li>• Vite for fast development</li>
                        <li>• Framer Motion for animations</li>
                        <li>• Tailwind CSS for styling</li>
                        <li>• Lucide React for icons</li>
                      </ul>
                    </div>
                  </div>

                  <h3 className="text-xl font-bold text-white mt-8 mb-4">Security Standards Compliance</h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="text-center p-3 bg-gray-900/30 rounded-lg">
                      <div className="text-green-400 font-bold">OWASP Top 10</div>
                      <div className="text-xs text-gray-400">Full Coverage</div>
                    </div>
                    <div className="text-center p-3 bg-gray-900/30 rounded-lg">
                      <div className="text-green-400 font-bold">CVE Database</div>
                      <div className="text-xs text-gray-400">Real-time Updates</div>
                    </div>
                    <div className="text-center p-3 bg-gray-900/30 rounded-lg">
                      <div className="text-green-400 font-bold">CVSS Scoring</div>
                      <div className="text-xs text-gray-400">v3.1 Standard</div>
                    </div>
                    <div className="text-center p-3 bg-gray-900/30 rounded-lg">
                      <div className="text-green-400 font-bold">NIST Framework</div>
                      <div className="text-xs text-gray-400">Aligned</div>
                    </div>
                  </div>

                  <div className="bg-gray-900/30 rounded-lg p-4 border border-gray-600/30 mt-6">
                    <p className="text-gray-300 text-sm">
                      <strong className="text-yellow-400">Important:</strong> This tool is designed for educational purposes and ethical security testing only. 
                      Always ensure you have explicit permission before scanning any target. Use responsibly and in accordance with applicable laws and regulations.
        </p>
      </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Footer */}
      <footer className="relative z-10 border-t border-gray-700/50 bg-black/50 backdrop-blur-sm mt-16">
        <div className="container mx-auto px-6 py-8">
          <div className="text-center text-gray-400">
            <p>&copy; 2025 CYBY. Built with ❤️ for cybersecurity education and ethical hacking.</p>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default App
