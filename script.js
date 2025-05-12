document.getElementById("checkButton").addEventListener("click", checkURL);

async function checkURL() {
    const url = document.getElementById("urlInput").value;
    if (!url) {
        alert("Please enter a URL.");
        return;
    }

    const resultElement = document.getElementById("result");
    resultElement.innerHTML = "Checking...";

    try {
        const googleSafe = await checkGoogleSafe(url);
        const virusTotal = await checkVirusTotal(url);

        if (googleSafe.isMalicious || virusTotal.isMalicious) {
            resultElement.innerHTML = `<span style="color: red;">The URL is malicious!</span>`;
        } else {
            resultElement.innerHTML = `<span style="color: green;">The URL is safe!</span>`;
        }
    } catch (error) {
        resultElement.innerHTML = `<span style="color: red;">Error: ${error.message}</span>`;
    }
}

async function checkGoogleSafe(url) {
    const apiKey = 'AIzaSyDa8QrFovPA9WUQ89ro1Xgzyx6xEtjHlmE'; // Replace with your Google API Key
    const endpoint = `https://safeweb.googleapis.com/v1beta1/lookup?key=${apiKey}`;
    const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            url: url
        })
    });
    const data = await response.json();
    return { isMalicious: data.safeBrowsing && data.safeBrowsing.malicious };
}

async function checkVirusTotal(url) {
    const apiKey = 'b9d41d768ad3e995d3f772c19d3f405164b9a9a0407af7534f476fce677155c4'; // Replace with your VirusTotal API Key
    const endpoint = `https://www.virustotal.com/api/v3/urls/${btoa(url)}`;
    const response = await fetch(endpoint, {
        headers: {
            'x-apikey': apiKey,
        }
    });

    const data = await response.json();
    return { isMalicious: data.data.attributes.last_analysis_stats.malicious > 0 };
}
