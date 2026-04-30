import { useState } from 'react'
import { Shield, Code, FileText, AlertTriangle, CheckCircle, Search, TerminalSquare, Box } from 'lucide-react'

// Dummy code predefined in the editor for quick demo purposes
const DEFAULT_CODE = `import hashlib
from flask import Flask

app = Flask(__name__)

# Vulnerability 1: Hardcoded Secret
api_key = "super_secret_key_12345"

# Vulnerability 2: Weak Crypto
def hash_data(data):
    return hashlib.md5(data.encode())

# Vulnerability 3: Insecure Defaults
if __name__ == '__main__':
    app.run(debug=True)
`

const DEFAULT_DEPS = `requests==2.20.0
urllib3==1.24.1
flask==2.0.1
`

function App() {
  const [sourceCode, setSourceCode] = useState(DEFAULT_CODE)
  const [dependencies, setDependencies] = useState(DEFAULT_DEPS)
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)
  const [error, setError] = useState(null)

  const handleScan = async () => {
    setLoading(true)
    setError(null)
    setResults(null)

    try {
      const response = await fetch('http://localhost:8000/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_code: sourceCode,
          dependencies: dependencies,
          file_name: "main.py"
        })
      })

      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}`)
      }

      const data = await response.json()
      setResults(data)

    } catch (err) {
      setError(err.message || 'Failed to connect to backend engine.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="app-container">
      {/* Navbar Section */}
      <nav className="navbar">
        <h1><Shield size={28} /> SecURI DevSecOps Engine</h1>
      </nav>

      <div className="main-content">
        
        {/* Left Pane - Inputs */}
        <div className="split-pane left-pane">
          <div className="input-group" style={{ flex: 2 }}>
            <label><Code size={18} /> Source Code (main.py)</label>
            <textarea 
              value={sourceCode} 
              onChange={(e) => setSourceCode(e.target.value)}
              placeholder="Paste your Python code here..."
            />
          </div>
          
          <div className="input-group" style={{ flex: 1 }}>
            <label><FileText size={18} /> Dependencies (requirements.txt)</label>
            <textarea 
              value={dependencies} 
              onChange={(e) => setDependencies(e.target.value)}
              placeholder="requests==2.20.0"
            />
          </div>

          <button className="scan-button" onClick={handleScan} disabled={loading}>
            {loading ? <Search className="animate-spin" size={20} /> : <TerminalSquare size={20} />}
            {loading ? 'Analyzing Source & Dependencies...' : 'Run Security Scan'}
          </button>
          
          {error && (
            <div className="card" style={{borderColor: '#ef4444', backgroundColor: '#450a0a', color: '#fca5a5'}}>
              <AlertTriangle size={20} style={{marginBottom: "0.5rem"}}/>
              <p style={{margin: 0}}>{error}</p>
            </div>
          )}
        </div>

        {/* Right Pane - Results */}
        <div className="split-pane right-pane">
          {results ? (
            <>
              <div className="results-header">
                <h2>Scan Report</h2>
                <p>Found {results.sast_findings.length} misconfiguration(s) and {results.sca_findings.length} vulnerable dependenc(ies).</p>
              </div>

              {/* SAST Findings */}
              <h3 className="section-title"><Code size={20} /> SAST (Code Analysis)</h3>
              {results.sast_findings.length === 0 ? (
                <div className="no-issues"><CheckCircle size={20}/> No misconfigurations found!</div>
              ) : (
                results.sast_findings.map((finding, idx) => (
                  <div key={idx} className="card">
                    <div className="card-header">
                      <h4 className="card-title">{finding.issue_type}</h4>
                      <span className={`badge badge-${finding.severity}`}>{finding.severity}</span>
                    </div>
                    <div className="card-meta">File: {finding.file_name} | Line: {finding.line_number}</div>
                    <p className="card-description">{finding.description}</p>
                  </div>
                ))
              )}

              {/* SCA Findings */}
              <h3 className="section-title"><Box size={20} /> SCA (Dependency Analysys)</h3>
              {results.sca_findings.length === 0 ? (
                <div className="no-issues"><CheckCircle size={20}/> All dependencies are secure!</div>
              ) : (
                results.sca_findings.map((finding, idx) => (
                  <div key={idx} className="card">
                    <div className="card-header">
                      <h4 className="card-title">{finding.cve_id}</h4>
                      <span className={`badge badge-${finding.severity}`}>{finding.severity}</span>
                    </div>
                    <div className="card-meta">Package: {finding.package} v{finding.version}</div>
                    <p className="card-description">{finding.description}</p>
                  </div>
                ))
              )}
            </>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#64748b' }}>
              <Shield size={64} style={{ opacity: 0.2, marginBottom: '1rem' }} />
              <h3>Awaiting Code to Analyze</h3>
              <p>Hit "Run Security Scan" to trigger the CI/CD pipeline hook.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default App
