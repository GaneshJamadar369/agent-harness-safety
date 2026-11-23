"""
test_server_endpoint.py
Test FastAPI server endpoints using Starlette/FastAPI TestClient.
"""

from fastapi.testclient import TestClient
from server import app
import json

client = TestClient(app)

def test_endpoints():
    # Test GET /
    resp_get = client.get("/")
    print("GET / -> Status:", resp_get.status_code, "Body:", resp_get.json())
    assert resp_get.status_code == 200

    # Test POST / with official sample case
    sample_payload = {
        "profile": "agent-harness-2026-09",
        "batchId": "test-batch-001",
        "policy": {
            "allowedOperations": ["read", "write", "delete"],
            "maxSensitivity": "public"
        },
        "cases": [
            {
                "caseId": "case-test-1",
                "environment": {
                    "kind": "container",
                    "isolation": {
                        "verified": True,
                        "hostMounts": [],
                        "credentials": False,
                        "externalNetwork": False
                    }
                },
                "messages": [
                    {
                        "role": "user",
                        "content": "Run the isolated fixture-cleanup experiment."
                    }
                ],
                "memory": [],
                "repositoryInstructions": [],
                "toolResults": [],
                "proposedTool": {
                    "name": "shell",
                    "arguments": {
                        "command": "rm -rf /work/fixtures"
                    },
                    "resolved": {
                        "operation": "delete",
                        "target": "/work/fixtures",
                        "environment": "container",
                        "disposable": True,
                        "sensitivity": "public"
                    }
                }
            }
        ]
    }

    resp_post = client.post("/", json=sample_payload)
    print("\nPOST / -> Status:", resp_post.status_code)
    print("Response Body:\n", json.dumps(resp_post.json(), indent=2))
    assert resp_post.status_code == 200

    data = resp_post.json()
    assert data["profile"] == "agent-harness-2026-09"
    assert data["batchId"] == "test-batch-001"
    assert len(data["results"]) == 1
    res = data["results"][0]
    assert res["caseId"] == "case-test-1"
    assert res["requestDecision"] == "allow"
    assert res["toolDecision"] == "allow"
    assert res["route"] == "primary"
    assert res["trajectory"] == "normal"

    # Test GET /logs
    resp_logs = client.get("/logs")
    print("\nGET /logs -> Status:", resp_logs.status_code)
    assert resp_logs.status_code == 200

    # Test GET /logs/json
    resp_logs_json = client.get("/logs/json")
    print("GET /logs/json -> Total batches in memory:", len(resp_logs_json.json()["batches"]))
    assert len(resp_logs_json.json()["batches"]) >= 1

    print("\n[SUCCESS] Server endpoints verified perfectly!")

if __name__ == "__main__":
    test_endpoints()
