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

app.post("/scan",(req,res)=>{

    try{

        const repo=req.body.repoPath;

        if(!repo){

            return res.status(400).json({

                success:false,

                message:"Repository path missing."

            });

        }

        const findings=[];

        let scannedFiles=0;

        if (!fs.existsSync(repo) || !fs.statSync(repo).isDirectory()) {
            return res.status(400).json({
                success: false,
                message: "Invalid repository path."
            });
        }

        scanFolder(repo);

        res.json({

            success:true,

            repository:repo,

            totalFiles:scannedFiles,

            totalSecrets:findings.length,

            findings

        });

        function scanFolder(folder){

            const files=

            fs.readdirSync(folder);

            for(const file of files){

                const full=

                path.join(folder,file);

                const stat=

                fs.statSync(full);

                if(stat.isDirectory()){

                    if(

                        [

                            ".git",

                            "node_modules",

                            "dist",

                            "build",

                            ".next"

                        ].includes(file)

                    ){

                        continue;

                    }

                    scanFolder(full);

                }

                else{

                    if(

                        !/\.(js|ts|jsx|tsx|java|py|cpp|c|cs|go|php|json|env|yml|yaml|txt|md)$/i

                        .test(full)

                    ){

                        continue;

                    }

                    scannedFiles++;

                    const text=

                    fs.readFileSync(

                        full,

                        "utf8"

                    );

                    const lines=

                    text.split("\n");

                    lines.forEach(

                        (line,index)=>{

                            patterns.forEach(

                                pattern=>{

                                    const matches=

                                    line.match(

                                        pattern.regex

                                    );

                                    if(matches){

                                        matches.forEach(

                                            match=>{

                                                findings.push({

                                                    file:full,

                                                    line:index+1,

                                                    type:pattern.name,

                                                    severity:pattern.severity,

                                                    value:

                                                    match.substring(0,10)+"********"

                                                });

                                            }

                                        );

                                    }

                                }

                            );

                        }

                    );

                }

            }

        }

    }

    catch(err){

        res.status(500).json({

            success:false,

            message:err.message

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