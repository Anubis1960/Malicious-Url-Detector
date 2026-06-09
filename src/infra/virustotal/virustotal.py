import os
import time
import requests
import dotenv
dotenv.load_dotenv()

api_key = os.getenv("VIRUS_TOTAL_API_KEY")

def run_virustotal_check(url):
    headers = {"x-apikey": api_key, "Content-Type": "application/x-www-form-urlencoded"}

    submit_resp = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data=f"url={requests.utils.quote(url, safe='')}"
    )
    if submit_resp.status_code != 200:
        return {"error": f"VT submission failed: {submit_resp.status_code} {submit_resp.text}"}

    analysis_id = submit_resp.json().get("data", {}).get("id")
    if not analysis_id:
        return {"error": "No analysis ID returned from VirusTotal"}

    for attempt in range(6):
        time.sleep(3)
        result_resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers={"x-apikey": api_key}
        )
        if result_resp.status_code != 200:
            continue
        data = result_resp.json()
        status = data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            stats = data["data"]["attributes"]["stats"]
            results = data["data"]["attributes"]["results"]

            malicious_engines = [
                eng for eng, res in results.items()
                if res.get("category") in ("malicious", "suspicious")
            ]

            total = sum(stats.values())
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            return {
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": stats.get("undetected", 0),
                "total_engines": total,
                "flagging_engines": malicious_engines[:10],
                "verdict": "clean" if (malicious + suspicious) == 0 else (
                    "suspicious" if malicious == 0 else "malicious"
                ),
            }

    return {"error": "VirusTotal analysis timed out"}