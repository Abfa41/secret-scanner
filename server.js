import express from "express";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ======================================
// MULTER
// ======================================

const upload = multer({
    dest: "scans/"
});

// ======================================
// STATIC FILES
// ======================================

app.use(express.static(path.join(__dirname, "public")));

app.use(express.json());

// ======================================
// SECRET PATTERNS
// ======================================

const patterns = [

    {
        name: "AWS Access Key",
        severity: "High",
        regex: /AKIA[0-9A-Z]{16}/g
    },

    {
        name: "GitHub Token",
        severity: "High",
        regex: /ghp_[A-Za-z0-9]{36}/g
    },

    {
        name: "OpenAI API Key",
        severity: "High",
        regex: /sk-[A-Za-z0-9]{20,}/g
    },

    {
        name: "JWT Token",
        severity: "Medium",
        regex: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g
    },

    {
        name: "Bearer Token",
        severity: "Medium",
        regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g
    },

    {
        name: "MongoDB URI",
        severity: "High",
        regex: /mongodb(\+srv)?:\/\/[^\s'"]+/g
    },

    {
        name: "Private Key",
        severity: "Critical",
        regex: /-----BEGIN[\s\S]*?PRIVATE KEY-----/g
    },

    {
        name: "Password Assignment",
        severity: "Medium",
        regex: /(password|passwd|pwd)\s*[:=]\s*["']?[^"'\n]+["']?/gi
    },

    {
        name: "Secret Variable",
        severity: "Low",
        regex: /(secret|token|apikey|api_key)\s*[:=]\s*["']?[^"'\n]+["']?/gi
    }

];

// ======================================
// HOME
// ======================================

app.get("/", (req, res) => {

    res.sendFile(
        path.join(__dirname, "public", "index.html")
    );

});

// ======================================
// SCAN FILE
// ======================================

app.post("/scan", upload.single("file"), (req, res) => {

    try {

        if (!req.file) {

            return res.status(400).json({

                success: false,

                message: "No file uploaded."

            });

        }

        const fileContent = fs.readFileSync(
            req.file.path,
            "utf8"
        );

        const lines = fileContent.split("\n");

        const findings = [];

        lines.forEach((line, index) => {

            patterns.forEach(pattern => {

                const matches = line.match(pattern.regex);

                if (matches) {

                    matches.forEach(match => {

                        findings.push({

                            line: index + 1,

                            type: pattern.name,

                            severity: pattern.severity,

                            value:
                                match.length > 20
                                    ? match.substring(0, 8) +
                                      "********"
                                    : match

                        });

                    });

                }

            });

        });

        fs.unlinkSync(req.file.path);

        res.json({

            success: true,

            file: req.file.originalname,

            totalSecrets: findings.length,

            findings

        });

    }

    catch (err) {

        console.error(err);

        res.status(500).json({

            success: false,

            message: "Scanning failed."

        });

    }

});

// ======================================
// START SERVER
// ======================================

app.listen(PORT, () => {

    console.log(

        `🚀 Secret Scanner running at http://localhost:${PORT}`

    );

});