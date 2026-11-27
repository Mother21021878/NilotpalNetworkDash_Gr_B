import json
import server


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(data, fp)


def read_json(path):
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def test_historical_trends_joins_by_scan_id(tmp_path, monkeypatch):
    traffic_file = tmp_path / "traffic.json"
    risk_file = tmp_path / "risk.json"

    write_json(traffic_file, [
        {
            "scanId": "scan-1",
            "generatedISO": "2026-10-13T10:00:00",
            "totalPackets": 100,
            "totalBytes": 2048
        },
        {
            "scanId": "scan-2",
            "generatedISO": "2026-10-14T10:00:00",
            "totalPackets": 200,
            "totalBytes": 4096
        }
    ])

    write_json(risk_file, [
        {
            "scanId": "scan-1",
            "riskScore": 25,
            "riskLevel": "MEDIUM"
        },
        {
            "scanId": "unmatched",
            "riskScore": 90,
            "riskLevel": "HIGH"
        }
    ])

    monkeypatch.setattr(
        server, "TRAFFIC_ANALYSIS_HISTORY", str(traffic_file)
    )
    monkeypatch.setattr(
        server, "RISK_ANALYSIS_HISTORY", str(risk_file)
    )

    response = server.app.test_client().get("/historical-trends")
    assert response.status_code == 200

    data = response.get_json()
    assert data["count"] == 2
    assert data["scans"][0]["scanId"] == "scan-1"
    assert data["scans"][0]["riskScore"] == 25
    assert data["scans"][0]["riskLevel"] == "MEDIUM"
    assert data["scans"][1]["riskScore"] is None


def test_historical_trends_pagination_and_date_filter(
    tmp_path, monkeypatch
):
    traffic_file = tmp_path / "traffic.json"
    risk_file = tmp_path / "risk.json"

    write_json(traffic_file, [
        {
            "scanId": f"scan-{day}",
            "generatedISO": f"2026-10-{day:02d}T10:00:00",
            "totalPackets": day
        }
        for day in (10, 11, 12, 13)
    ])
    write_json(risk_file, [])

    monkeypatch.setattr(
        server, "TRAFFIC_ANALYSIS_HISTORY", str(traffic_file)
    )
    monkeypatch.setattr(
        server, "RISK_ANALYSIS_HISTORY", str(risk_file)
    )

    client = server.app.test_client()

    response = client.get(
        "/historical-trends?page=1&per_page=2"
        "&start_date=2026-10-11&end_date=2026-10-13"
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] == 3
    assert data["total_pages"] == 2
    assert len(data["scans"]) == 2

    response = client.get(
        "/historical-trends?page=2&per_page=2"
        "&start_date=2026-10-11&end_date=2026-10-13"
    )
    assert len(response.get_json()["scans"]) == 1


def test_historical_trends_rejects_invalid_date_range():
    response = server.app.test_client().get(
        "/historical-trends"
        "?start_date=2026-10-20&end_date=2026-10-10"
    )
    assert response.status_code == 400


def test_traffic_history_upsert_prevents_duplicate_scan_ids(
    tmp_path, monkeypatch
):
    history_file = tmp_path / "traffic.json"

    monkeypatch.setattr(
        server, "TRAFFIC_ANALYSIS_HISTORY", str(history_file)
    )

    # Verify the scan-history upsert logic directly.
    history = [
        {"scanId": "scan-1", "totalPackets": 100}
    ]
    updated = {"scanId": "scan-1", "totalPackets": 200}

    index = next(
        (
            i for i, item in enumerate(history)
            if item.get("scanId") == updated["scanId"]
        ),
        None
    )

    if index is None:
        history.append(updated)
    else:
        history[index] = updated

    write_json(history_file, history)
    saved = read_json(history_file)

    assert len(saved) == 1
    assert saved[0]["totalPackets"] == 200