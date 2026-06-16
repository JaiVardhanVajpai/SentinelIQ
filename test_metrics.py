import asyncio
import httpx
import json
from datetime import datetime

BACKEND = "http://localhost:8000"

MALICIOUS = [
    "185.220.101.45", "185.220.101.34",
    "185.220.101.1",  "185.220.101.2",
    "185.220.101.3",  "185.220.101.4",
    "185.220.101.5",  "185.220.101.6",
    "185.220.101.7",  "185.220.101.8",
    "185.220.101.9",  "185.220.101.10",
    "185.220.101.11", "185.220.101.12",
    "185.220.101.13", "185.220.101.14",
    "185.220.101.15", "185.220.101.16",
    "185.220.101.17", "185.220.101.18",
    "185.220.101.19", "185.220.101.20",
    "185.220.100.240","185.220.100.241",
    "185.220.100.242","185.220.100.243",
    "185.220.100.244","185.220.100.245",
    "185.220.100.246","185.220.100.247",
    "185.220.102.8",  "185.220.102.9",
    "185.220.102.10", "185.220.102.11",
    "185.220.102.12", "185.220.102.13",
    "185.220.102.244","185.220.102.245",
    "185.220.102.246","185.220.102.247",
    "45.142.212.100", "45.142.212.101",
    "45.142.212.102", "45.142.212.103",
    "193.32.127.130", "193.32.127.131",
    "193.32.127.132", "193.32.127.133",
    "89.248.167.131", "89.248.167.130",
]

CLEAN = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "208.67.222.222", "208.67.220.220", "9.9.9.9",
    "149.112.112.112", "76.76.19.19", "76.76.2.0",
    "https://google.com", "https://github.com",
    "https://microsoft.com", "https://apple.com",
    "https://amazon.com", "https://cloudflare.com",
    "https://wikipedia.org", "https://stackoverflow.com",
    "https://python.org", "https://reactjs.org",
    "https://mongodb.com", "https://fastapi.tiangolo.com",
    "https://vercel.com", "https://render.com",
    "https://npmjs.com", "https://pypi.org",
    "https://linkedin.com", "https://youtube.com",
    "https://twitter.com", "https://reddit.com",
    "192.168.1.1", "10.0.0.1", "172.16.0.1",
    "192.168.0.1", "10.10.10.1", "172.31.0.1",
    "192.168.100.1", "10.0.0.254", "172.16.255.254",
    "192.168.1.254", "10.255.255.255", "172.20.0.1",
    "https://bbc.com", "https://reuters.com",
    "https://techcrunch.com", "https://wired.com",
    "https://medium.com", "https://dev.to",
    "https://docker.com", "https://kubernetes.io"
]

async def test_indicator(client, indicator, expected):
    try:
        if indicator.startswith("http"):
            r = await client.get(
                f"{BACKEND}/analyze-url",
                params={"url": indicator},
                timeout=30
            )
        else:
            r = await client.get(
                f"{BACKEND}/analyze-ip",
                params={"ip": indicator},
                timeout=30
            )

        if r.status_code == 200:
            data = r.json()
            score = data.get("risk_score", 0)
            verdict = data.get("verdict", "UNKNOWN")
            predicted = "MALICIOUS" if score >= 70 else "CLEAN"
            correct = (predicted == expected)
            return {
                "indicator": indicator,
                "expected": expected,
                "predicted": predicted,
                "risk_score": score,
                "verdict": verdict,
                "correct": correct
            }
        else:
            return {
                "indicator": indicator,
                "expected": expected,
                "predicted": "ERROR",
                "risk_score": None,
                "verdict": "API_ERROR",
                "correct": False
            }
    except Exception as e:
        return {
            "indicator": indicator,
            "expected": expected,
            "predicted": "ERROR",
            "risk_score": None,
            "verdict": str(e)[:50],
            "correct": False
        }

async def run_metrics():
    print(f"Starting metrics test — {len(MALICIOUS)} malicious + {len(CLEAN)} clean")
    print(f"Total: {len(MALICIOUS) + len(CLEAN)} indicators\n")

    results = []

    async with httpx.AsyncClient() as client:
        print("Testing malicious indicators...")
        for i, ind in enumerate(MALICIOUS):
            r = await test_indicator(client, ind, "MALICIOUS")
            results.append(r)
            status = "[OK]" if r["correct"] else "[X] "
            print(f"  [{i+1:2d}] {status} {ind[:45]:<45} score={r['risk_score']} pred={r['predicted']}")
            await asyncio.sleep(0.5)

        print("\nTesting clean indicators...")
        for i, ind in enumerate(CLEAN):
            r = await test_indicator(client, ind, "CLEAN")
            results.append(r)
            status = "[OK]" if r["correct"] else "[X] "
            print(f"  [{i+1:2d}] {status} {ind[:45]:<45} score={r['risk_score']} pred={r['predicted']}")
            await asyncio.sleep(0.5)

    mal_results   = [r for r in results if r["expected"] == "MALICIOUS"]
    clean_results = [r for r in results if r["expected"] == "CLEAN"]

    tp = sum(1 for r in mal_results   if r["predicted"] == "MALICIOUS")
    fn = sum(1 for r in mal_results   if r["predicted"] != "MALICIOUS")
    tn = sum(1 for r in clean_results if r["predicted"] == "CLEAN")
    fp = sum(1 for r in clean_results if r["predicted"] != "CLEAN")

    tpr = round(tp / len(mal_results) * 100, 1) if mal_results else 0
    fpr = round(fp / len(clean_results) * 100, 1) if clean_results else 0
    acc = round((tp + tn) / len(results) * 100, 1) if results else 0

    errors = sum(1 for r in results if r["predicted"] == "ERROR")

    print("\n" + "="*55)
    print("SENTINELIQ METRICS REPORT")
    print("="*55)
    print(f"Test Date:          {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"Total Tested:       {len(results)}")
    print(f"Malicious Sample:   {len(mal_results)}")
    print(f"Clean Sample:       {len(clean_results)}")
    print(f"API Errors:         {errors}")
    print("-"*55)
    print(f"True Positives:     {tp}  (correctly flagged malicious)")
    print(f"False Negatives:    {fn}  (missed malicious)")
    print(f"True Negatives:     {tn}  (correctly passed clean)")
    print(f"False Positives:    {fp}  (wrongly flagged clean)")
    print("-"*55)
    print(f"TRUE POSITIVE RATE: {tpr}%")
    print(f"FALSE POSITIVE RATE:{fpr}%")
    print(f"ACCURACY:           {acc}%")
    print("="*55)

    with open("metrics_results.json", "w") as f:
        json.dump({
            "date": datetime.now().isoformat(),
            "total": len(results),
            "tpr": tpr,
            "fpr": fpr,
            "accuracy": acc,
            "tp": tp, "fn": fn, "tn": tn, "fp": fp,
            "errors": errors,
            "results": results
        }, f, indent=2)

    print(f"\nFull results saved to metrics_results.json")
    print("\nINTERVIEW ANSWER:")
    print(f'I tested SentinelIQ on {len(results)} indicators —')
    print(f'{len(mal_results)} known malicious, {len(clean_results)} clean.')
    print(f'True positive rate: {tpr}%')
    print(f'False positive rate: {fpr}%')
    print(f'Overall accuracy: {acc}%')

if __name__ == "__main__":
    asyncio.run(run_metrics())
