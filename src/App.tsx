import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, Zap, AlertTriangle, CheckCircle, Play, Eye, Lock, Code, Bug, Search, Key, Activity, Download } from 'lucide-react'
import { SiReact, SiPython, SiTypescript, SiTailwindcss, SiFramer, SiFastapi } from 'react-icons/si'
import { API_BASE_URL } from './config'
import './App.css'
import Login from './components/Login'
import SignUp from './components/SignUp'
import { HeroGeometric } from './components/ui/hero-geometric'
import { WavyBackground } from './components/ui/wavy-background'
import LogoLoop from './components/ui/LogoLoop'

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
  const [currentView, setCurrentView] = useState<'home' | 'scanner' | 'about' | 'login' | 'signup'>('login')
  const [targetUrl, setTargetUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [scanTypes, setScanTypes] = useState(['sqli', 'xss', 'csrf', 'headers', 'dir_traversal', 'auth_bypass'])
  const [generatingPDF, setGeneratingPDF] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [isLoggedIn, setIsLoggedIn] = useState(false)

  //Callback function
  const handleLogout = () => {
    setIsLoggedIn(false)
    setCurrentView('login')
    setScanResult(null)
    setTargetUrl('')
  }

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
      console.log('Connecting to backend:', API_BASE_URL);
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
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const result = await response.json()
      setScanResult(result)
      setScanProgress(100)
    } catch (error) {
      console.error('Scan error:', error)
      console.error('Backend URL:', API_BASE_URL)
      const err = error as Error;
      // Better error message
      if (err.message.includes('Failed to fetch')) {
        alert(`Cannot connect to backend server at ${API_BASE_URL}.\n\nPlease check:\n1. Backend is deployed and running\n2. CORS is configured correctly\n3. Network connection is stable`)
      } else {
        alert(`Scan failed: ${err.message}`)
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
      const err = error as Error;
      if (err.message.includes('Failed to fetch')) {
        alert('Cannot connect to backend server. Please make sure the backend is running on port 8000.')
      } else {
        alert(`PDF generation failed: ${err.message}`)
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
    { id: 'auth_bypass', label: 'Auth Bypass', icon: <Key className="w-4 h-4" />, description: 'Authentication bypass' }
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
      <nav className="relative z-50 border-b border-white/10 bg-black/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <motion.div
              className="flex items-center space-x-3"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5 }}
            >
              <div className="relative">
                <Shield className="w-10 h-10 text-white" />
                <Activity className="w-5 h-5 text-gray-400 absolute -top-1 -right-1" />
              </div>
              <span className="text-3xl font-bold text-white tracking-wider">
                CYBY
              </span>
            </motion.div>

            <div className="flex items-center space-x-8">
              {(isLoggedIn ? ['HOME', 'SCANNER', 'ABOUT'] : ['LOGIN', 'SIGNUP']).map((view) => (
                <button
                  key={view.toLowerCase()}
                  onClick={() => setCurrentView(view.toLowerCase() as any)}
                  className={`transition-all duration-200 hover:text-white ${currentView === view.toLowerCase()
                    ? 'text-white border-b-2 border-white'
                    : 'text-gray-400 hover:border-b-2 hover:border-white/50'
                    }`}
                >
                  {view}
                </button>
              ))}
              {isLoggedIn && (
                <button
                  onClick={handleLogout}
                  className="text-gray-400 hover:text-white hover:border-b-2 hover:border-white/50 transition-all duration-200"
                >
                  LOGOUT
                </button>
              )}
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
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.5 }}
            >
              <HeroGeometric
                badge="Security Scanner"
                title1="Protect Your Systems"
                title2="AI-Powered Vulnerability Detection"
                description="Advanced ML algorithms detect 6 vulnerability types with 80%+ accuracy in real-time"
              >
                <div className="max-w-6xl mx-auto">
                  {/* CTA Section */}
                  <motion.div
                    className="text-center mb-12"
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8, delay: 1.0 }}
                  >
                    <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
                      Secure Your Digital Assets Today
                    </h2>
                    <p className="text-gray-400 text-lg max-w-2xl mx-auto">
                      Identify vulnerabilities before attackers do with our AI-powered security scanner
                    </p>
                  </motion.div>

                  {/* CTA Buttons */}
                  <motion.div
                    className="flex flex-col sm:flex-row gap-4 justify-center mb-16"
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8, delay: 1.2 }}
                  >
                    <button
                      onClick={() => setCurrentView('scanner')}
                      className="px-8 py-4 bg-white text-black font-bold rounded-lg hover:bg-gray-200 transition-all duration-300 transform hover:scale-105 hover:shadow-lg hover:shadow-white/25 flex items-center justify-center gap-3"
                    >
                      <Play className="w-5 h-5" />
                      <span>Start Security Scan</span>
                    </button>

                    <button
                      onClick={() => setCurrentView('about')}
                      className="px-8 py-4 border border-white/30 text-white font-bold rounded-lg hover:bg-white/10 transition-all duration-300"
                    >
                      Learn More
                    </button>
                  </motion.div>

                  {/* Features Grid */}
                  <div className="grid md:grid-cols-3 gap-8 mb-16">
                    {[
                      {
                        icon: <Shield className="w-12 h-12 text-gray-300" />,
                        title: "Automated Scanning",
                        description: "Comprehensive vulnerability detection across 6 major security attack vectors"
                      },
                      {
                        icon: <Zap className="w-12 h-12 text-gray-300" />,
                        title: "Real-time Scanning",
                        description: "Lightning-fast comprehensive security assessment"
                      },
                      {
                        icon: <Lock className="w-12 h-12 text-gray-300" />,
                        title: "Professional Reports",
                        description: "Detailed PDF reports and remediation guides"
                      }
                    ].map((feature, index) => (
                      <motion.div
                        key={index}
                        className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-8 hover:border-white/30 transition-all duration-300"
                        initial={{ opacity: 0, y: 30 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.5, delay: 1.4 + index * 0.1 }}
                        whileHover={{ scale: 1.05 }}
                      >
                        <div className="mb-4">{feature.icon}</div>
                        <h3 className="text-xl font-bold mb-3 text-white">{feature.title}</h3>
                        <p className="text-gray-400">{feature.description}</p>
                      </motion.div>
                    ))}
                  </div>

                  {/* Advanced Security Features */}
                  <motion.div
                    className="relative overflow-hidden rounded-2xl"
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, delay: 1.8 }}
                  >
                    {/* Background Gradient */}
                    <div className="absolute inset-0 bg-gradient-to-br from-white/5 via-white/10 to-white/5 backdrop-blur-sm"></div>
                    <div className="absolute inset-0 bg-gradient-to-tr from-emerald-500/5 via-transparent to-cyan-500/5"></div>

                    <div className="relative border border-white/20 rounded-2xl p-10">
                      <div className="text-center mb-10">
                        <motion.div
                          initial={{ scale: 0.9, opacity: 0 }}
                          animate={{ scale: 1, opacity: 1 }}
                          transition={{ duration: 0.5, delay: 2.0 }}
                        >
                          <h2 className="text-4xl md:text-5xl font-bold mb-3 bg-gradient-to-r from-white via-gray-100 to-gray-300 bg-clip-text text-transparent">
                            Advanced Security Features
                          </h2>
                          <p className="text-gray-400 text-lg">Comprehensive protection across all attack vectors</p>
                        </motion.div>
                      </div>

                      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {[
                          {
                            name: 'SQL Injection',
                            icon: <Code className="w-8 h-8" />,
                            description: 'Database attack prevention',
                            gradient: 'from-red-500/20 to-orange-500/20',
                            borderGradient: 'from-red-500/50 to-orange-500/50',
                            iconBg: 'bg-red-500/10'
                          },
                          {
                            name: 'XSS Detection',
                            icon: <Bug className="w-8 h-8" />,
                            description: 'Script injection defense',
                            gradient: 'from-purple-500/20 to-pink-500/20',
                            borderGradient: 'from-purple-500/50 to-pink-500/50',
                            iconBg: 'bg-purple-500/10'
                          },
                          {
                            name: 'CSRF Protection',
                            icon: <Shield className="w-8 h-8" />,
                            description: 'Request forgery shield',
                            gradient: 'from-blue-500/20 to-cyan-500/20',
                            borderGradient: 'from-blue-500/50 to-cyan-500/50',
                            iconBg: 'bg-blue-500/10'
                          },
                          {
                            name: 'Directory Traversal',
                            icon: <Search className="w-8 h-8" />,
                            description: 'Path traversal blocking',
                            gradient: 'from-yellow-500/20 to-amber-500/20',
                            borderGradient: 'from-yellow-500/50 to-amber-500/50',
                            iconBg: 'bg-yellow-500/10'
                          },
                          {
                            name: 'Auth Bypass',
                            icon: <Key className="w-8 h-8" />,
                            description: 'Authentication security',
                            gradient: 'from-green-500/20 to-emerald-500/20',
                            borderGradient: 'from-green-500/50 to-emerald-500/50',
                            iconBg: 'bg-green-500/10'
                          },
                          {
                            name: 'Security Headers',
                            icon: <Lock className="w-8 h-8" />,
                            description: 'HTTP header validation',
                            gradient: 'from-indigo-500/20 to-violet-500/20',
                            borderGradient: 'from-indigo-500/50 to-violet-500/50',
                            iconBg: 'bg-indigo-500/10'
                          },
                        ].map((feature, index) => (
                          <motion.div
                            key={index}
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ duration: 0.5, delay: 2.1 + index * 0.1 }}
                            whileHover={{ scale: 1.05, y: -5 }}
                            className="group relative"
                          >
                            {/* Gradient Border Effect */}
                            <div className={`absolute inset-0 bg-gradient-to-br ${feature.borderGradient} rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 blur-sm`}></div>

                            {/* Card Content */}
                            <div className={`relative bg-gradient-to-br ${feature.gradient} backdrop-blur-sm border border-white/10 rounded-xl p-6 h-full transition-all duration-300 group-hover:border-white/30`}>
                              {/* Icon Container */}
                              <div className={`${feature.iconBg} w-16 h-16 rounded-lg flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300`}>
                                <span className="text-white">{feature.icon}</span>
                              </div>

                              {/* Text Content */}
                              <h3 className="text-xl font-bold text-white mb-2 group-hover:text-white transition-colors">
                                {feature.name}
                              </h3>
                              <p className="text-sm text-gray-400 group-hover:text-gray-300 transition-colors">
                                {feature.description}
                              </p>

                              {/* Hover Indicator */}
                              <div className="mt-4 flex items-center text-xs text-gray-500 group-hover:text-white transition-colors">
                                <CheckCircle className="w-4 h-4 mr-1" />
                                <span>Active</span>
                              </div>
                            </div>
                          </motion.div>
                        ))}
                      </div>

                      {/* Bottom Stats */}
                      <motion.div
                        className="mt-10 pt-8 border-t border-white/10"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 0.5, delay: 2.8 }}
                      >
                        <div className="grid grid-cols-2 gap-8 text-center max-w-md mx-auto">
                          <div>
                            <div className="text-3xl font-bold text-white mb-1">6</div>
                            <div className="text-sm text-gray-400">Attack Vectors</div>
                          </div>
                          <div>
                            <div className="text-3xl font-bold text-white mb-1">30+</div>
                            <div className="text-sm text-gray-400">Test Payloads</div>
                          </div>
                        </div>
                      </motion.div>
                    </div>
                  </motion.div>
                </div>
              </HeroGeometric>

              {/* Our Mission Section */}
              <motion.div
                className="container mx-auto px-6 py-16"
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 1.2 }}
              >
                <div className="max-w-6xl mx-auto">
                  <div className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl p-12">
                    <div className="text-center mb-12">
                      <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">Our Mission</h2>
                      <p className="text-xl text-gray-300 max-w-3xl mx-auto leading-relaxed">
                        Empowering organizations to build secure digital infrastructure through
                        intelligent, automated vulnerability detection and comprehensive security insights.
                      </p>
                    </div>

                    {/* Mission Stats */}
                    <div className="grid grid-cols-2 gap-8 mb-12 max-w-lg mx-auto">
                      <div className="text-center">
                        <div className="text-4xl font-bold text-white mb-2">6</div>
                        <div className="text-sm text-gray-400">Attack Vectors</div>
                      </div>
                      <div className="text-center">
                        <div className="text-4xl font-bold text-white mb-2">95%</div>
                        <div className="text-sm text-gray-400">False Positive Reduction</div>
                      </div>
                    </div>

                    {/* Mission Points */}
                    <div className="grid md:grid-cols-2 gap-6">
                      <div className="bg-white/5 rounded-xl p-6 border border-white/10">
                        <h3 className="text-xl font-bold text-white mb-3">Proactive Defense</h3>
                        <p className="text-gray-400">
                          Identify and neutralize security vulnerabilities before they can be exploited by malicious actors,
                          reducing the risk of data breaches and unauthorized access.
                        </p>
                      </div>
                      <div className="bg-white/5 rounded-xl p-6 border border-white/10">
                        <h3 className="text-xl font-bold text-white mb-3">AI-Powered Intelligence</h3>
                        <p className="text-gray-400">
                          Leverage advanced machine learning algorithms to detect complex attack patterns and anomalies
                          with industry-leading accuracy and minimal false positives.
                        </p>
                      </div>
                      <div className="bg-white/5 rounded-xl p-6 border border-white/10">
                        <h3 className="text-xl font-bold text-white mb-3">Comprehensive Coverage</h3>
                        <p className="text-gray-400">
                          Full OWASP Top 10 compliance with extended coverage for SQL Injection, XSS, CSRF,
                          Directory Traversal, Authentication Bypass, and Security Headers.
                        </p>
                      </div>
                      <div className="bg-white/5 rounded-xl p-6 border border-white/10">
                        <h3 className="text-xl font-bold text-white mb-3">Actionable Insights</h3>
                        <p className="text-gray-400">
                          Receive detailed PDF reports with executive summaries, technical findings,
                          and step-by-step remediation guides to fix vulnerabilities quickly.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>
            </motion.div>
          )}

          {currentView === 'scanner' && (
            <motion.div
              key="scanner"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.5 }}
            >
              <HeroGeometric
                badge="Security Scanner"
                title1="CYBY Security Scanner"
                title2="Advanced Vulnerability Detection"
                description="Comprehensive security testing across 6 attack vectors with AI-powered analysis"
              >
                <div className="max-w-6xl mx-auto mt-8">
                  {/* Scanner Input */}
                  <div className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-8 mb-8">
                    <div className="space-y-8">
                      {/* URL Input Section */}
                      <div>
                        <div className="flex items-center justify-between mb-3">
                          <label className="text-lg font-semibold text-white">
                            Target URL
                          </label>
                          <span className="text-xs text-gray-400 bg-white/5 px-3 py-1 rounded-full">
                            Step 1 of 2
                          </span>
                        </div>
                        <p className="text-sm text-gray-400 mb-4">
                          Enter the website URL you want to scan for security vulnerabilities
                        </p>
                        <input
                          type="url"
                          value={targetUrl}
                          onChange={(e) => setTargetUrl(e.target.value)}
                          placeholder="https://example.com"
                          className="w-full px-5 py-4 bg-white/5 border border-white/20 rounded-lg text-white placeholder-white/40 focus:border-white focus:ring-2 focus:ring-white/20 focus:outline-none transition-all text-lg"
                        />

                        {/* Quick Presets */}
                        <div className="mt-4">
                          <p className="text-xs text-gray-400 mb-2">Quick Test URLs:</p>
                          <div className="flex flex-wrap gap-2">
                            {[
                              'http://testphp.vulnweb.com/',
                              'http://testhtml5.vulnweb.com/',
                              'http://testasp.vulnweb.com/'
                            ].map((url) => (
                              <button
                                key={url}
                                onClick={() => setTargetUrl(url)}
                                className="text-xs px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 rounded-md text-gray-300 hover:text-white transition-all"
                              >
                                {url.replace('http://', '').replace('/', '')}
                              </button>
                            ))}
                          </div>
                        </div>
                      </div>

                      {/* Divider */}
                      <div className="border-t border-white/10"></div>

                      {/* Scan Types Section */}
                      <div>
                        <div className="flex items-center justify-between mb-3">
                          <label className="text-lg font-semibold text-white">
                            Select Scan Types
                          </label>
                          <span className="text-xs text-gray-400 bg-white/5 px-3 py-1 rounded-full">
                            Step 2 of 2
                          </span>
                        </div>
                        <p className="text-sm text-gray-400 mb-6">
                          Choose which vulnerability tests to run. Select all for comprehensive scanning.
                        </p>

                        {/* Select All Button */}
                        <div className="mb-4">
                          <button
                            onClick={() => {
                              if (scanTypes.length === scanTypeOptions.length) {
                                setScanTypes([]);
                              } else {
                                setScanTypes(scanTypeOptions.map(t => t.id));
                              }
                            }}
                            className="text-sm px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 rounded-lg text-white transition-all"
                          >
                            {scanTypes.length === scanTypeOptions.length ? 'Deselect All' : 'Select All'}
                          </button>
                        </div>

                        <div className="grid md:grid-cols-2 gap-3">
                          {scanTypeOptions.map((type) => (
                            <label
                              key={type.id}
                              className={`flex items-center justify-between p-5 rounded-xl cursor-pointer transition-all duration-200 ${scanTypes.includes(type.id)
                                ? 'bg-white/10 border-2 border-white/30'
                                : 'bg-white/5 border-2 border-white/10 hover:border-white/20 hover:bg-white/8'
                                }`}
                            >
                              <div className="flex items-center space-x-4 flex-1">
                                <div className={`w-12 h-12 flex items-center justify-center rounded-lg transition-all ${scanTypes.includes(type.id)
                                  ? 'bg-white/20 text-white'
                                  : 'bg-white/5 text-white/60'
                                  }`}>
                                  {type.icon}
                                </div>
                                <div className="flex-1">
                                  <div className="text-sm font-semibold text-white mb-1">
                                    {type.label}
                                  </div>
                                  <div className="text-xs text-gray-400">
                                    {type.description}
                                  </div>
                                </div>
                              </div>
                              <div className="flex items-center ml-3">
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
                                  className="w-5 h-5 text-white bg-white/10 border-white/20 rounded focus:ring-white/50 focus:ring-2"
                                />
                              </div>
                            </label>
                          ))}
                        </div>
                      </div>

                      {/* Divider */}
                      <div className="border-t border-white/10"></div>

                      <div className="space-y-4">
                        {/* Scan Info */}
                        {!scanning && scanTypes.length > 0 && (
                          <div className="bg-white/5 rounded-lg p-4 border border-white/10">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center space-x-3">
                                <Shield className="w-5 h-5 text-white" />
                                <span className="text-sm text-white font-medium">
                                  Ready to scan
                                </span>
                              </div>
                              <span className="text-xs text-gray-400 bg-white/5 px-3 py-1 rounded-full">
                                {scanTypes.length} {scanTypes.length === 1 ? 'test' : 'tests'} selected
                              </span>
                            </div>
                          </div>
                        )}

                        {/* Progress Bar */}
                        {scanning && (
                          <div className="w-full">
                            <div className="flex justify-between text-sm text-white mb-3">
                              <span className="font-medium">Scanning in progress...</span>
                              <span className="font-bold">{Math.round(scanProgress)}%</span>
                            </div>
                            <div className="w-full bg-white/10 rounded-full h-3 overflow-hidden">
                              <motion.div
                                className="bg-gradient-to-r from-white via-gray-200 to-white h-3 rounded-full relative"
                                initial={{ width: 0 }}
                                animate={{ width: `${scanProgress}%` }}
                                transition={{ duration: 0.3 }}
                              >
                                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-pulse"></div>
                              </motion.div>
                            </div>
                            <p className="text-xs text-gray-400 mt-2">
                              Analyzing security vulnerabilities across {scanTypes.length} attack vectors
                            </p>
                          </div>
                        )}

                        {/* Main Scan Button */}
                        <button
                          onClick={runScan}
                          disabled={scanning || scanTypes.length === 0}
                          className={`
                            w-full px-8 py-5 rounded-xl font-bold text-lg
                            transition-all duration-300 transform
                            ${scanning || scanTypes.length === 0
                              ? 'bg-white/10 text-white/40 cursor-not-allowed'
                              : 'bg-black text-white hover:bg-gray-900 hover:scale-[1.02] hover:shadow-2xl hover:shadow-black/50 border-2 border-white/20 hover:border-white/40'
                            }
                          `}
                        >
                          {scanning ? (
                            <div className="flex items-center justify-center space-x-3">
                              <div className="w-6 h-6 border-3 border-white/20 border-t-white rounded-full animate-spin"></div>
                              <span>Running Security Scan...</span>
                            </div>
                          ) : (
                            <div className="flex items-center justify-center space-x-3">
                              <Shield className="w-6 h-6" />
                              <span>Start Comprehensive Security Scan</span>
                              {scanTypes.length > 0 && (
                                <span className="ml-2 px-2 py-0.5 bg-white/20 rounded-full text-sm">
                                  {scanTypes.length}
                                </span>
                              )}
                            </div>
                          )}
                        </button>

                        {/* Helper Text */}
                        {scanTypes.length === 0 && !scanning && (
                          <p className="text-center text-sm text-gray-400">
                            Please select at least one scan type to begin
                          </p>
                        )}

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
                      <div className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-8">
                        <h3 className="text-2xl font-bold mb-4 text-white">Security Assessment Results</h3>
                        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                          <div className="text-center">
                            <div className="text-3xl font-bold text-red-400">
                              {scanResult.risk_score}
                            </div>
                            <div className="text-sm text-white/60">Risk Score</div>
                          </div>
                          <div className="text-center">
                            <div className="text-3xl font-bold text-yellow-400">
                              {scanResult.total_vulnerabilities}
                            </div>
                            <div className="text-sm text-white/60">Total Issues</div>
                          </div>
                          <div className="text-center">
                            <div className="text-3xl font-bold text-red-400">
                              {(scanResult.scan_summary.vulnerability_breakdown as any).critical || 0}
                            </div>
                            <div className="text-sm text-white/60">Critical</div>
                          </div>
                          <div className="text-center">
                            <div className="text-3xl font-bold text-orange-400">
                              {scanResult.scan_summary.vulnerability_breakdown.high}
                            </div>
                            <div className="text-sm text-white/60">High</div>
                          </div>
                          <div className="text-center">
                            <div className="text-3xl font-bold text-yellow-400">
                              {scanResult.scan_summary.vulnerability_breakdown.medium}
                            </div>
                            <div className="text-sm text-white/60">Medium</div>
                          </div>
                        </div>
                      </div>

                      {/* Vulnerabilities List */}
                      <div className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-8">
                        <h3 className="text-2xl font-bold mb-6 text-white">Detected Vulnerabilities</h3>
                        {scanResult.vulnerabilities.length > 0 ? (
                          <div className="space-y-4">
                            {scanResult.vulnerabilities.map((vuln, index) => (
                              <div key={index} className="bg-white/5 border border-white/10 rounded-lg p-6 hover:border-red-400/30 transition-all">
                                <div className="flex items-start justify-between mb-3">
                                  <div className="flex items-center space-x-3">
                                    {getSeverityIcon(vuln.severity)}
                                    <h4 className="text-lg font-semibold text-white">{vuln.type}</h4>
                                  </div>
                                  <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getSeverityColor(vuln.severity)}`}>
                                    {vuln.severity}
                                  </span>
                                </div>
                                <p className="text-white/70 mb-3">{vuln.description}</p>
                                <div className="bg-white/5 rounded-lg p-4">
                                  <p className="text-sm text-white/60 mb-2"><strong className="text-white/80">Recommendation:</strong></p>
                                  <p className="text-sm text-white/70">{vuln.recommendation}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="text-center py-8">
                            <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-4" />
                            <p className="text-white text-lg">No vulnerabilities found!</p>
                            <p className="text-white/60 text-sm">The target appears to be secure against the tested attack vectors.</p>
                          </div>
                        )}
                      </div>
                    </motion.div>
                  )}
                </div>
              </HeroGeometric>
            </motion.div>
          )}

          {currentView === 'about' && (
            <motion.div
              key="about"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.5 }}
            >
              <WavyBackground
                colors={["#404040", "#525252", "#737373", "#525252", "#404040"]}
                waveWidth={60}
                backgroundFill="#000000"
                blur={12}
                speed="slow"
                waveOpacity={0.2}
                containerClassName="min-h-screen"
                className="w-full max-w-6xl mx-auto px-6 pt-24 pb-16"
              >
                <div className="max-w-5xl mx-auto">
                  <h1 className="text-6xl font-bold mb-16 text-center bg-gradient-to-r from-white via-gray-300 to-gray-500 bg-clip-text text-transparent">
                    About
                  </h1>

                  {/* Project Overview */}
                  <div className="bg-black/40 backdrop-blur-md border-2 border-white/20 rounded-2xl p-10 mb-8">
                    <div className="flex items-center space-x-3 mb-6">
                      <Shield className="w-8 h-8 text-white" />
                      <h2 className="text-3xl font-bold text-white">What is CYBY?</h2>
                    </div>
                    <p className="text-gray-300 text-lg leading-relaxed">
                      CYBY is a comprehensive AI-powered web security scanning platform designed for educational
                      and ethical testing purposes. The system combines traditional vulnerability detection techniques
                      with advanced machine learning to provide accurate and actionable security assessments.
                    </p>
                  </div>

                  {/* Core Features */}
                  <div className="bg-black/40 backdrop-blur-md border-2 border-white/20 rounded-2xl p-10 mb-8">
                    <div className="flex items-center space-x-3 mb-8">
                      <Zap className="w-8 h-8 text-white" />
                      <h3 className="text-3xl font-bold text-white">Core Features</h3>
                    </div>
                    <div className="grid md:grid-cols-2 gap-6">
                      {[
                        {
                          icon: <Code className="w-6 h-6" />,
                          title: "Comprehensive Vulnerability Scanning",
                          desc: "Detects SQL Injection, XSS, CSRF, Security Headers, Directory Traversal, and Authentication Bypass vulnerabilities"
                        },
                        {
                          icon: <Shield className="w-6 h-6" />,
                          title: "AI-Enhanced Detection",
                          desc: "Machine learning algorithms identify anomalous responses and reduce false positives by 95%"
                        },
                        {
                          icon: <Activity className="w-6 h-6" />,
                          title: "Real-time Threat Intelligence",
                          desc: "Integration with latest CVE databases and security advisories for up-to-date protection"
                        },
                        {
                          icon: <Download className="w-6 h-6" />,
                          title: "Professional Reporting",
                          desc: "Generate detailed PDF reports with executive summaries and remediation guides"
                        },
                        {
                          icon: <Lock className="w-6 h-6" />,
                          title: "Ethical Safety Controls",
                          desc: "SAFE MODE ensures responsible testing with approved demo targets only"
                        },
                        {
                          icon: <CheckCircle className="w-6 h-6" />,
                          title: "OWASP Compliance",
                          desc: "Full coverage of OWASP Top 10 security risks and industry best practices"
                        }
                      ].map((feature, index) => (
                        <div key={index} className="bg-white/5 border border-white/10 rounded-xl p-6 hover:bg-white/10 hover:border-white/30 transition-all">
                          <div className="flex items-start space-x-4">
                            <div className="bg-white/10 p-3 rounded-lg text-white flex-shrink-0">
                              {feature.icon}
                            </div>
                            <div>
                              <h4 className="font-bold text-white mb-2">{feature.title}</h4>
                              <p className="text-gray-400 text-sm">{feature.desc}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Technology Stack */}
                  <div className="bg-black/40 backdrop-blur-md border-2 border-white/20 rounded-2xl p-6 mb-8">
                    <div className="flex items-center space-x-2 mb-4">
                      <Code className="w-6 h-6 text-white" />
                      <h3 className="text-2xl font-bold text-white">Technology Stack</h3>
                    </div>

                    <div className="grid md:grid-cols-2 gap-4">
                      {/* Backend Technologies */}
                      <div>
                        <div className="flex items-center space-x-2 mb-2">
                          <div className="bg-gradient-to-r from-white to-gray-400 px-2.5 py-1 rounded-md">
                            <span className="font-bold text-black text-xs">Backend</span>
                          </div>
                        </div>
                        <div className="space-y-2">
                          <div className="bg-white/5 border border-white/10 rounded-lg p-2 hover:bg-white/10 hover:border-white/30 transition-all">
                            <div className="flex items-center space-x-2">
                              <SiPython className="w-5 h-5 text-[#3776AB] flex-shrink-0" />
                              <div>
                                <h4 className="font-semibold text-white text-xs">Python 3.11+</h4>
                                <p className="text-gray-400 text-[10px]">Core backend language</p>
                              </div>
                            </div>
                          </div>

                          <div className="bg-white/5 border border-white/10 rounded-xl p-5 hover:bg-white/10 hover:border-white/30 transition-all group">
                            <div className="flex items-center space-x-3 mb-3">
                              <SiFastapi className="w-8 h-8 text-[#009688]" />
                              <h4 className="font-bold text-white text-lg">FastAPI</h4>
                            </div>
                            <p className="text-gray-400 text-sm">High-performance REST API framework</p>
                          </div>

                          <div className="bg-white/5 border border-white/10 rounded-xl p-5 hover:bg-white/10 hover:border-white/30 transition-all group">
                            <div className="flex items-center space-x-3 mb-3">
                              <Code className="w-8 h-8 text-white" />
                              <h4 className="font-bold text-white text-lg">BeautifulSoup4</h4>
                            </div>
                            <p className="text-gray-400 text-sm">HTML parsing and web scraping</p>
                          </div>

                          <div className="bg-white/5 border border-white/10 rounded-xl p-5 hover:bg-white/10 hover:border-white/30 transition-all group">
                            <div className="flex items-center space-x-3 mb-3">
                              <Activity className="w-8 h-8 text-white" />
                              <h4 className="font-bold text-white text-lg">Requests</h4>
                            </div>
                            <p className="text-gray-400 text-sm">HTTP library for security testing</p>
                          </div>

                          <div className="bg-white/5 border border-white/10 rounded-xl p-5 hover:bg-white/10 hover:border-white/30 transition-all group">
                            <div className="flex items-center space-x-3 mb-3">
                              <Zap className="w-8 h-8 text-white" />
                              <h4 className="font-bold text-white text-lg">Scikit-learn</h4>
                            </div>
                            <p className="text-gray-400 text-sm">Machine learning for threat detection</p>
                          </div>

                          <div className="bg-white/5 border border-white/10 rounded-xl p-5 hover:bg-white/10 hover:border-white/30 transition-all group">
                            <div className="flex items-center space-x-3 mb-3">
                              <Download className="w-8 h-8 text-white" />
                              <h4 className="font-bold text-white text-lg">ReportLab</h4>
                            </div>
                            <p className="text-gray-400 text-sm">Professional PDF report generation</p>
                          </div>
                        </div>
                      </div>

                      {/* Frontend Technologies */}
                      <div>
                        <div className="flex items-center space-x-2 mb-4">
                          <div className="bg-gradient-to-r from-white to-gray-400 px-3 py-1.5 rounded-lg">
                            <span className="font-bold text-black text-sm">Frontend</span>
                          </div>
                        </div>
                        <div className="space-y-3">
                          <div className="bg-white/5 border border-white/10 rounded-xl p-5 hover:bg-white/10 hover:border-white/30 transition-all group">
                            <div className="flex items-center space-x-3 mb-3">
                              <SiReact className="w-8 h-8 text-[#61DAFB]" />
                              <h4 className="font-bold text-white text-lg">React 18</h4>
                            </div>
                            <p className="text-gray-400 text-sm">Modern UI library with TypeScript</p>
                          </div>

                          <div className="bg-white/5 border border-white/10 rounded-xl p-5 hover:bg-white/10 hover:border-white/30 transition-all group">
                            <div className="flex items-center space-x-3 mb-3">
                              <SiTypescript className="w-8 h-8 text-[#3178C6]" />
                              <h4 className="font-bold text-white text-lg">TypeScript</h4>
                            </div>
                            <p className="text-gray-400 text-sm">Type-safe JavaScript development</p>
                          </div>

                          <div className="bg-white/5 border border-white/10 rounded-xl p-5 hover:bg-white/10 hover:border-white/30 transition-all group">
                            <div className="flex items-center space-x-3 mb-3">
                              <Zap className="w-8 h-8 text-[#646CFF]" />
                              <h4 className="font-bold text-white text-lg">Vite</h4>
                            </div>
                            <p className="text-gray-400 text-sm">Lightning-fast build tool</p>
                          </div>

                          <div className="bg-white/5 border border-white/10 rounded-xl p-5 hover:bg-white/10 hover:border-white/30 transition-all group">
                            <div className="flex items-center space-x-3 mb-3">
                              <SiFramer className="w-8 h-8 text-[#0055FF]" />
                              <h4 className="font-bold text-white text-lg">Framer Motion</h4>
                            </div>
                            <p className="text-gray-400 text-sm">Smooth animations and transitions</p>
                          </div>

                          <div className="bg-white/5 border border-white/10 rounded-xl p-5 hover:bg-white/10 hover:border-white/30 transition-all group">
                            <div className="flex items-center space-x-3 mb-3">
                              <SiTailwindcss className="w-8 h-8 text-[#06B6D4]" />
                              <h4 className="font-bold text-white text-lg">Tailwind CSS</h4>
                            </div>
                            <p className="text-gray-400 text-sm">Utility-first CSS framework</p>
                          </div>

                          <div className="bg-white/5 border border-white/10 rounded-xl p-5 hover:bg-white/10 hover:border-white/30 transition-all group">
                            <div className="flex items-center space-x-3 mb-3">
                              <Shield className="w-8 h-8 text-white" />
                              <h4 className="font-bold text-white text-lg">Lucide React</h4>
                            </div>
                            <p className="text-gray-400 text-sm">Beautiful icon library</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Technology Partners */}
                  <div className="bg-black/40 backdrop-blur-md border-2 border-white/20 rounded-2xl p-10 mb-8">
                    <div style={{ height: '120px', position: 'relative', overflow: 'hidden' }}>
                      <LogoLoop
                        logos={[
                          { node: <SiReact size={48} color="#61DAFB" />, title: "React", href: "https://react.dev" },
                          { node: <SiPython size={48} color="#3776AB" />, title: "Python", href: "https://www.python.org" },
                          { node: <SiTypescript size={48} color="#3178C6" />, title: "TypeScript", href: "https://www.typescriptlang.org" },
                          { node: <SiTailwindcss size={48} color="#06B6D4" />, title: "Tailwind CSS", href: "https://tailwindcss.com" },
                          { node: <SiFramer size={48} color="#0055FF" />, title: "Framer Motion", href: "https://www.framer.com/motion" },
                          { node: <SiFastapi size={48} color="#009688" />, title: "FastAPI", href: "https://fastapi.tiangolo.com" },
                        ]}
                        speed={80}
                        direction="left"
                        logoHeight={48}
                        gap={60}
                        hoverSpeed={20}
                        scaleOnHover
                        fadeOut
                        fadeOutColor="#000000"
                        ariaLabel="Technology stack"
                      />
                    </div>
                  </div>
                </div>
              </WavyBackground>
            </motion.div>
          )}

          {currentView === 'login' && (
            <motion.div
              key="login"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.5 }}
              className="w-full"
            >
              <Login onNavigate={(view) => setCurrentView(view)} onLogin={() => setIsLoggedIn(true)} />
            </motion.div>
          )
          }

          {
            currentView === 'signup' && (
              <motion.div
                key="signup"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.5 }}
                className="w-full"
              >
                <SignUp onNavigate={(view) => setCurrentView(view)} />
              </motion.div>
            )
          }
        </AnimatePresence >
      </main >

      {/* Footer */}
      < footer className="relative z-10 border-t border-gray-700/50 bg-black/50 backdrop-blur-sm mt-16" >
        <div className="container mx-auto px-6 py-8">
          <div className="text-center text-gray-400">
            <p>&copy; 2025 CYBY. Built for cybersecurity education and ethical hacking.</p>
          </div>
        </div>
      </footer >
    </div >
  )
}

export default App
