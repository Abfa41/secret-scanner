// =====================================
// DOM ELEMENTS
// =====================================

const fileInput =
document.getElementById("fileInput");

const scanBtn =
document.getElementById("scanBtn");

const downloadBtn =
document.getElementById("downloadBtn");

const results =
document.getElementById("results");

const historyList =
document.getElementById("historyList");

const fileName =
document.getElementById("fileName");

const secretCount =
document.getElementById("secretCount");

const scanCount =
document.getElementById("scanCount");



// =====================================
// DATA
// =====================================

let lastReport = null;

let history =
JSON.parse(
    localStorage.getItem(
        "scanHistory"
    )
) || [];



// =====================================
// LOAD HISTORY
// =====================================

function loadHistory(){

    scanCount.textContent =
    history.length;

    if(history.length===0){

        historyList.innerHTML=`

        <div class="empty">

            <i class="fa-solid fa-clock-rotate-left"></i>

            <p>

                No scans have been performed yet.

            </p>

        </div>

        `;

        return;

    }

    historyList.innerHTML="";

    history
    .slice()
    .reverse()
    .forEach(scan=>{

        const item =
        document.createElement("div");

        item.className =
        "history-item";

        item.innerHTML=`

            <div>

                <strong>

                    ${scan.file}

                </strong>

            </div>

            <div>

                ${scan.totalSecrets}
                secret(s)

            </div>

            <div>

                ${scan.date}

            </div>

        `;

        historyList.appendChild(item);

    });

}



// =====================================
// DISPLAY RESULTS
// =====================================

function displayResults(report){

    lastReport = report;

    fileName.textContent =
    report.file;

    secretCount.textContent =
    report.totalSecrets;

    results.innerHTML="";

    if(report.totalSecrets===0){

        results.innerHTML=`

        <div class="empty">

            <i class="fa-solid fa-circle-check"></i>

            <p>

                No secrets detected.

            </p>

        </div>

        `;

        return;

    }

    report.findings.forEach(secret=>{

        const card =
        document.createElement("div");

        card.className =
        "result-item";

        card.innerHTML=`

            <h3>

                ${secret.type}

            </h3>

            <p>

                <strong>Line:</strong>

                ${secret.line}

            </p>

            <p>

                <strong>Detected:</strong>

                ${secret.value}

            </p>

            <span class="badge ${secret.severity.toLowerCase()}">

                ${secret.severity}

            </span>

        `;

        results.appendChild(card);

    });

}

// =====================================
// SCAN FILE
// =====================================

async function scanFile(){

    const file =

        fileInput.files[0];



    if(!file){

        alert(

            "Please select a file first."

        );

        return;

    }



    scanBtn.disabled = true;

    scanBtn.innerHTML =

        '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';



    const formData =

        new FormData();

    formData.append(

        "file",

        file

    );



    try{

        const response =

            await fetch(

                "/scan",

                {

                    method:"POST",

                    body:formData

                }

            );



        const report =

            await response.json();



        if(!report.success){

            throw new Error(

                report.message ||

                "Scanning failed."

            );

        }



        displayResults(report);



        history.push({

            file:report.file,

            totalSecrets:report.totalSecrets,

            date:new Date().toLocaleString()

        });



        localStorage.setItem(

            "scanHistory",

            JSON.stringify(history)

        );



        loadHistory();

    }

    catch(err){

        console.error(err);



        alert(

            err.message ||

            "Something went wrong while scanning."

        );

    }

    finally{

        scanBtn.disabled = false;

        scanBtn.innerHTML =

            '<i class="fa-solid fa-magnifying-glass"></i> Scan File';

    }

}



// =====================================
// DOWNLOAD JSON REPORT
// =====================================

function downloadReport(){

    if(!lastReport){

        alert(

            "Run a scan first."

        );

        return;

    }



    const blob =

        new Blob(

            [

                JSON.stringify(

                    lastReport,

                    null,

                    2

                )

            ],

            {

                type:"application/json"

            }

        );



    const url =

        URL.createObjectURL(blob);



    const link =

        document.createElement("a");



    link.href = url;

    link.download =

        "secret-scan-report.json";



    document.body.appendChild(link);

    link.click();

    document.body.removeChild(link);



    URL.revokeObjectURL(url);

}



// =====================================
// EVENTS
// =====================================

scanBtn.addEventListener(

    "click",

    scanFile

);



downloadBtn.addEventListener(

    "click",

    downloadReport

);

loadHistory();