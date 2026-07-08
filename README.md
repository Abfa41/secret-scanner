# 🛡️ Secret Scanner

A security-focused web application developed for the **HackWeek Challenge 2026**. The application scans source code and configuration files to detect accidentally exposed secrets such as API keys, passwords, authentication tokens, private keys, and database connection strings before they become security risks.

---

## ✨ Features

- 🔍 Scan uploaded source code files
- 🔐 Detect exposed API Keys
- 🔑 Detect Passwords
- 🪙 Detect Authentication Tokens
- 🐙 Detect GitHub Personal Access Tokens
- ☁️ Detect AWS Access Keys
- 🍃 Detect MongoDB Connection Strings
- 🔒 Detect Private Keys
- 📊 Security Dashboard
- 📜 Scan History
- 💾 Download JSON Scan Report
- 📱 Responsive UI
- 🎨 Modern Glassmorphism Design

---

## 🛠️ Technologies Used

- HTML5
- CSS3
- JavaScript (ES6)
- Node.js
- Express.js
- Multer
- Regular Expressions (Regex)

---

## 📁 Project Structure

```
secret-scanner/

│
├── public/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── scans/
│
├── package.json
├── server.js
└── README.md
```

---

## ⚙️ Installation

Clone the repository

```bash
git clone <repository-url>
```

Move inside the project

```bash
cd secret-scanner
```

Install dependencies

```bash
npm install
```

Run the application

```bash
npm start
```

Open

```
http://localhost:3000
```

---

## 🚀 How to Use

1. Launch the application.
2. Upload a source code or configuration file.
3. Click **Scan File**.
4. View the detected secrets with severity levels.
5. Review the scan history.
6. Download the JSON report if required.

---

## 📸 Demo

Record a short screen recording showing:

- Launching the application
- Uploading a sample source code file
- Detecting exposed secrets
- Viewing scan history
- Downloading the JSON report

---

## 🔮 Future Improvements

- GitHub Repository Scanning
- ZIP Archive Scanning
- Recursive Folder Scanning
- Custom Regex Rules
- PDF Security Reports
- Email Notifications
- User Authentication
- CI/CD Integration (Git Hooks)

---

## 👨‍💻 Author

Developed for the **HackWeek Challenge 2026**.