# SecURI CI/CD DevSecOps Engine

An advanced static analysis and dependency scanning tool designed to integrate seamlessly into modern CI/CD pipelines. This tool uncovers both hidden CVEs in dependencies and insecure configurations in source code (e.g., hardcoded secrets, weak cryptography, and debugging flags left enabled).
Live Server: https://uco-bank-hackathon-qo1l.vercel.app/

## 🚀 Features

*   **SAST (Static Application Security Testing):**
    *   Uses Python's `ast` module to statically analyze code.
    *   Detects weak cryptography (`hashlib.md5`, `hashlib.sha1`).
    *   Finds hardcoded secrets (tokens, api keys, passwords).
    *   Identifies insecure defaults (like `debug=True` in production code).
*   **SCA (Software Composition Analysis):**
    *   Parses `requirements.txt` to extract dependencies.
    *   Simulates cross-referencing against a vulnerability database (CVEs) to flag outdated/vulnerable packages.
*   **FastAPI Backend:**
    *   Rapid, asynchronous API serving the scanning engine.
    *   Built-in RESTful architecture, compatible with CI/CD runners (Jenkins, GitHub Actions, GitLab CI).

## 📁 Project Structure

```text
.
├── backend/
│   ├── main.py          # FastAPI application entry point
│   ├── models.py        # Pydantic schemas for request/response
│   ├── sast.py          # Core SAST engine utilizing Python's AST
│   ├── sca.py           # Core SCA engine for requirements parsing
│   └── requirements.txt # Python dependencies
└── frontend/
    ├── src/             
    │   ├── App.jsx      # Main React Dashboard Component
    │   └── index.css    # Custom DevSecOps Dark Theme UI
    ├── package.json     # Node dependencies (Vite + React)
    └── vite.config.js   # Vite Builder logic
```

## 🛠️ Installation & Setup

You will need two terminals running to test the complete application natively. 

### 1. Backend API (Terminal 1)
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --host localhost --port 8000 --reload
```

### 2. React UI Dashboard (Terminal 2)
Ensure you have Node.js installed.
```bash
cd frontend
npm install
npm run dev
```
Navigate your browser to `http://localhost:3000` to see the fully rendered Dashboard.

## 💻 Running the Server

Start the FastAPI application using Uvicorn:

```bash
uvicorn main:app --host localhost --port 8000 --reload
```

The API will be available at `http://localhost:8000`. You can access the interactive Swagger UI documentation at `http://localhost:8000/docs`.

## 📡 API Usage

### `POST /scan`

Accepts source code and a list of dependencies to be scanned.

## 🧪 Testing the API

There are multiple ways to test the tool:

### 1. Using the automated Python Script (Recommended)
We have included a `test_api.py` script containing dummy vulnerable code and dependencies. Run it in a new terminal:
```bash
python test_api.py
```

### 2. Using the Interactive Swagger UI
FastAPI comes with a beautiful automated testing interface.
1. Navigate your web browser to: [http://localhost:8000/docs](http://localhost:8000/docs).
2. Click on the green `POST /scan` row.
3. Click the **"Try it out"** button.
4. Replace the Request body with this exact dummy JSON:
```json
{
  "source_code": "import hashlib\napi_key = \"secret123\"\napp.run(debug=True)\nmy_hash = hashlib.md5(b'test')",
  "dependencies": "requests==2.20.0"
}
```
5. Click **Execute** to see the vulnerabilities returned immediately.

### 3. Using PowerShell (`Invoke-RestMethod`)
```powershell
$body = @{
    source_code = "import hashlib`napi_key=`"secret`"`napp.run(debug=True)"
    dependencies = "requests==2.20.0"
} | ConvertTo-Json

Invoke-RestMethod -Uri http://localhost:8000/scan -Method Post -Body $body -ContentType "application/json"
```

**Expected Response Payload:**
```json
{
  "sast_findings": [
    {
      "issue_type": "Hardcoded Secret",
      "description": "Possible hardcoded secret assigned to variable 'api_key'.",
      "file_name": "main.py",
      "line_number": 2,
      "severity": "CRITICAL"
    },
    {
      "issue_type": "Insecure Default",
      "description": "Found 'debug=True' passed as an argument. This is insecure for production.",
      "file_name": "main.py",
      "line_number": 3,
      "severity": "MEDIUM"
    }
  ],
  "sca_findings": [
    {
      "package": "requests",
      "version": "2.20.0",
      "cve_id": "CVE-2018-18074",
      "severity": "HIGH",
      "description": "The Requests package before 2.20.0 sends an HTTP Authorization header to an http URI upon receiving a redirect."
    }
  ]
}
```

## 🔬 Testing in Colab / Jupyter

If you want to quickly test the core logic without throwing up the full FastAPI server, you can use the code contained within `backend/notebook_test.py`. Simply copy its contents into a Colab notebook cell and execute it.
