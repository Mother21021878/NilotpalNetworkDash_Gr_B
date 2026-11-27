import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CACHE_FOLDER = os.path.join(BASE_DIR, "pcapCache")

TRAFFIC_CACHE = os.path.join(
    CACHE_FOLDER,
    "traffic_analysis.json"
)

RISK_CACHE = os.path.join(
    CACHE_FOLDER,
    "risk_analysis.json"
)

RISK_HISTORY = os.path.join(
    CACHE_FOLDER,
    "risk_history.json"
)

def analyse_risk():

    if not os.path.exists(TRAFFIC_CACHE):

        return {
            "status":"ERROR",
            "message":"traffic_analysis.json not found."
        }

    try:

        with open(
            TRAFFIC_CACHE,
            "r",
            encoding="utf-8"
        ) as fp:

            traffic = json.load(fp)

            totalPackets = traffic.get(
                "totalPackets",
                0
            )

            packetRate = traffic.get(
                "packetRate",
                0
            )

            throughput = traffic.get(
                "throughputMbps",
                0
            )

            protocols = traffic.get(
                "protocols",
                {}
            )

            topTalkers = traffic.get(
                "topTalkers",
                []
            )

            uploadDownloadRatio = traffic.get(
                "uploadDownloadRatio",
                {}
            )
    except Exception as e:

            return {
                "status":"ERROR",
                "message":str(e)
            }

    riskScore = 0
    recommendations = []

    # Heavy Traffic
    if packetRate > 500: riskScore += 15

    # High Throughput
    if throughput > 100: riskScore += 15

    # Too much ARP
    arp = protocols.get("ARP", 0)

    if arp > 500: riskScore += 10

    #Too much DNS
    dns = protocols.get("DNS", 0)

    if dns > 300: riskScore += 10


    upload = uploadDownloadRatio.get("upload", 0)
    download = uploadDownloadRatio.get("download", 0)

    if download > 0 and upload > (download * 2):
        riskScore += 5
        recommendations.append(
            "Upload traffic is significantly higher than download traffic."
        )

    riskScore = max(0, min(riskScore, 100))

    if riskScore < 20: riskLevel = "LOW"

    elif riskScore < 50: riskLevel = "MEDIUM"

    elif riskScore < 80: riskLevel = "HIGH"

    else:
        riskLevel = "CRITICAL"

    if arp > 500:
        recommendations.append("High ARP activity detected.")

    if dns > 300:
        recommendations.append("DNS traffic is unusually high.")

    if throughput > 100:
        recommendations.append("Network throughput is above threshold.")

    if not recommendations:
        recommendations.append("No abnormal activity detected.")

    result = {
        "status": "SUCCESS",
        "generated": datetime.now().strftime("%d-%b-%Y %H:%M:%S"),
        "generatedISO": datetime.now().isoformat(),
        "riskScore": riskScore,
        "riskLevel": riskLevel,
        "recommendations": recommendations,
        "recommendationCount": len(recommendations),
        "totalPackets": totalPackets,
        "packetRate": packetRate,
        "throughput": throughput,
        "uploadDownloadRatio": uploadDownloadRatio,
        "protocols": protocols,
        "topTalkers": topTalkers
    }
    
    with open(RISK_CACHE, "w", encoding="utf-8") as fp:
        json.dump(result, fp, indent=4)

    history = {

        "generated":
            result["generated"],
        "riskScore":
            riskScore,
        "riskLevel":
            riskLevel,
        "totalPackets":
            totalPackets,
        "packetRate":
            packetRate,
        "throughput":
            throughput
    }

    with open(RISK_HISTORY, "w", encoding="utf-8") as fp:
        json.dump(history, fp, indent=4 )
    '''
    print("=" * 70)
    print("Risk Analysis Updated Successfully")
    print(f"Generated          : {result['generated']}")
    print(f"Risk Score         : {riskScore}")
    print(f"Risk Level         : {riskLevel}")
    print(f"Total Packets      : {totalPackets}")
    print(f"Packet Rate        : {packetRate}")
    print(f"Throughput         : {throughput}")
    print(f"Recommendations    : {len(recommendations)}")
    print("=" * 70)
    '''
    return result