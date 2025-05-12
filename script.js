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
    const apiKey = 'YOUR_GOOGLE_API_KEY'; // Replace with your Google API Key
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
    const apiKey = 'YOUR_VIRUSTOTAL_API_KEY'; // Replace with your VirusTotal API Key
    const endpoint = `https://www.virustotal.com/api/v3/urls/${btoa(url)}`;
    const response = await fetch(endpoint, {
        headers: {
            'x-apikey': apiKey,
        }
    });

    const data = await response.json();
    return { isMalicious: data.data.attributes.last_analysis_stats.malicious > 0 };
}
