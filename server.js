import express from "express";
import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import simpleGit from "simple-git";
import { fileURLToPath } from "url";

const app = express();

const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ======================================
// MIDDLEWARE
// ======================================

app.use(express.json());

app.use(express.static(path.join(__dirname,"public")));

// ======================================
// SECRET PATTERNS
// ======================================

const patterns=[

    {
        name:"AWS Access Key",
        severity:"High",
        regex:/AKIA[0-9A-Z]{16}/g
    },

    {
        name:"GitHub Token",
        severity:"High",
        regex:/ghp_[A-Za-z0-9]{36}/g
    },

    {
        name:"OpenAI API Key",
        severity:"High",
        regex:/sk-[A-Za-z0-9]{20,}/g
    },

    {
        name:"JWT Token",
        severity:"Medium",
        regex:/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g
    },

    {
        name:"Bearer Token",
        severity:"Medium",
        regex:/Bearer\s+[A-Za-z0-9\-._~+/]+=*/g
    },

    {
        name:"MongoDB URI",
        severity:"High",
        regex:/mongodb(\+srv)?:\/\/[^\s'"]+/g
    },

    {
        name:"Private Key",
        severity:"Critical",
        regex:/-----BEGIN[\s\S]*?PRIVATE KEY-----/g
    },

    {
        name:"Password Assignment",
        severity:"Medium",
        regex:/(password|passwd|pwd)\s*[:=]\s*["']?[^"'\n]+["']?/gi
    },

    {
        name:"Secret Variable",
        severity:"Low",
        regex:/(secret|token|apikey|api_key)\s*[:=]\s*["']?[^"'\n]+["']?/gi
    }

];

// ======================================
// HOME
// ======================================

app.get("/",(req,res)=>{

    res.sendFile(

        path.join(

            __dirname,

            "public",

            "index.html"

        )

    );

});

// ======================================
// CREATE TEMP DIRECTORY
// ======================================

function createTempDirectory(){

    return path.join(

        os.tmpdir(),

        crypto.randomUUID()

    );

}

// ======================================
// VALIDATE GITHUB URL
// ======================================

function validateRepository(url){

    try{

        const parsed=new URL(url);

        return parsed.hostname==="github.com";

    }

    catch{

        return false;

    }

}

// ======================================
// CLONE REPOSITORY
// ======================================

async function cloneRepository(url){

    let repository=url.trim();

    if(!repository.endsWith(".git")){

        repository+=".git";

    }

    const tempDirectory=

        createTempDirectory();

    await simpleGit().clone(

        repository,

        tempDirectory

    );

    return{

        repository,

        tempDirectory

    };

}

// ======================================
// DELETE TEMP DIRECTORY
// ======================================

function removeDirectory(directory){

    if(fs.existsSync(directory)){

        fs.rmSync(

            directory,

            {

                recursive:true,

                force:true

            }

        );

    }

}

// ======================================
// SCAN REPOSITORY
// ======================================

app.post("/scan", async (req, res) => {

    let tempDirectory = "";

    try {

        const repo = req.body.repoPath;

        if (!repo) {

            return res.status(400).json({

                success: false,

                message: "GitHub repository URL is required."

            });

        }

        if (!validateRepository(repo)) {

            return res.status(400).json({

                success: false,

                message: "Please enter a valid GitHub repository URL."

            });

        }

        const cloned = await cloneRepository(repo);

        tempDirectory = cloned.tempDirectory;

        const findings = [];

        let scannedFiles = 0;

        scanFolder(tempDirectory);

        res.json({

            success: true,

            repository: repo,

            totalFiles: scannedFiles,

            totalSecrets: findings.length,

            findings

        });

        function scanFolder(folder) {

            const files = fs.readdirSync(folder);

            for (const file of files) {

                const fullPath = path.join(folder, file);

                const stat = fs.statSync(fullPath);

                if (stat.isDirectory()) {

                    if (

                        [

                            ".git",

                            "node_modules",

                            ".next",

                            "dist",

                            "build",

                            ".cache",

                            ".idea",

                            ".vscode"

                        ].includes(file)

                    ) {

                        continue;

                    }

                    scanFolder(fullPath);

                }

                else {

                    if (

                        !/\.(js|jsx|ts|tsx|java|py|cpp|c|cs|go|php|rb|swift|kt|json|env|yml|yaml|xml|properties|ini|txt|md)$/i.test(fullPath)

                    ) {

                        continue;

                    }

                    scannedFiles++;

                    let text = "";

                    try {

                        text = fs.readFileSync(

                            fullPath,

                            "utf8"

                        );

                    }

                    catch {

                        continue;

                    }

                    const lines = text.split("\n");

                    lines.forEach((line, index) => {

                        patterns.forEach(pattern => {

                            const matches = line.match(pattern.regex);

                            if (matches) {

                                matches.forEach(match => {

                                    findings.push({

                                        file: path.relative(

                                            tempDirectory,

                                            fullPath

                                        ),

                                        line: index + 1,

                                        type: pattern.name,

                                        severity: pattern.severity,

                                        value:

                                            match.length > 18

                                                ? match.substring(0, 10) + "********"

                                                : match

                                    });

                                });

                            }

                        });

                    });

                }

            }

        }

    }

    catch (err) {

        console.error(err);

        res.status(500).json({

            success: false,

            message: err.message

        });

    }

    finally {

        if (tempDirectory) {

            removeDirectory(tempDirectory);

        }

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