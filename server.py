"""
server.py
FastAPI Server for Agent Harness Safety Layer and Model Routing.
Ready for deployment on Render.
"""

import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import json
import time
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from classifier import evaluate_case

# Set up rich console and file logging
LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("harness-server")

app = FastAPI(
    title="Agent Harness Safety & Routing Service",
    version="1.0.0",
    description="Safety classification, tool authorization, model routing, and trajectory tracking."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store recent batches and logs in memory for web inspection (/logs)
RECENT_BATCHES: List[Dict[str, Any]] = []
MAX_STORED_BATCHES = 20

# Create logs directory if on filesystem
os.makedirs("logs/batches", exist_ok=True)


@app.get("/")
async def health_check():
    """Health check endpoint. Confirms service is live."""
    return {
        "status": "healthy",
        "service": "Agent Harness Safety Layer",
        "profile": "agent-harness-2026-09",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "recentBatchesProcessed": len(RECENT_BATCHES)
    }


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


def process_harness_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Core function that evaluates an incoming batch of cases against policy.
    Extensively logs every case, decision, and rationale.
    """
    start_time = time.time()
    profile = payload.get("profile", "agent-harness-2026-09")
    batch_id = payload.get("batchId", "unknown-batch")
    policy = payload.get("policy", {})
    cases = payload.get("cases", [])

    logger.info("=" * 80)
    logger.info(f"[BATCH RECEIVED] Batch ID: {batch_id} | Profile: {profile} | Cases Count: {len(cases)}")
    logger.info("=" * 80)

    # Log policy details
    logger.info("--- AUTHORITATIVE POLICY OBJECT ---")
    try:
        if isinstance(policy, (dict, list)):
            logger.info(json.dumps(policy, indent=2))
        else:
            logger.info(str(policy))
    except Exception as e:
        logger.info(f"(Failed to pretty-print policy: {e}) {policy}")
    logger.info("-----------------------------------")

    results: List[Dict[str, Any]] = []
    case_summaries: List[Dict[str, Any]] = []

    counts = {
        "requestDecision": {"allow": 0, "block": 0, "review": 0},
        "toolDecision": {"allow": 0, "block": 0, "review": 0, "none": 0},
        "route": {"primary": 0, "restricted": 0, "none": 0},
        "trajectory": {"normal": 0, "watch": 0, "intervene": 0}
    }

    for idx, case in enumerate(cases, start=1):
        case_id = case.get("caseId", f"unknown-{idx}")
        logger.info(f"\n[Case {idx}/{len(cases)}] Analyzing Case ID: {case_id}")

        # Extract case information for logging
        msgs = case.get("messages", [])
        user_msgs = [m.get("content", "") for m in msgs if isinstance(m, dict) and m.get("role") == "user"]
        env = case.get("environment", {})
        iso = env.get("isolation", {})
        proposed = case.get("proposedTool")
        rollback = case.get("rollbackPlan")
        memory = case.get("memory", [])
        repo_instructions = case.get("repositoryInstructions", [])

        logger.info(f"  |-- User Messages ({len(user_msgs)} turns):")
        for u_idx, u_msg in enumerate(user_msgs, 1):
            preview = (u_msg[:120] + "...") if len(u_msg) > 120 else u_msg
            logger.info(f"  |    Turn {u_idx}: {repr(preview)}")

        logger.info(f"  |-- Environment: kind={env.get('kind')}, isolation={iso}")
        
        if proposed:
            resolved = proposed.get("resolved", {})
            logger.info(f"  |-- Proposed Tool: name={proposed.get('name')}")
            logger.info(f"  |    Arguments: {proposed.get('arguments')}")
            logger.info(f"  |    Resolved: op={resolved.get('operation')}, target={resolved.get('target')}, env={resolved.get('environment')}, disposable={resolved.get('disposable')}, sensitivity={resolved.get('sensitivity')}")
        else:
            logger.info("  |-- Proposed Tool: None (no tool proposed)")

        if rollback:
            logger.info(f"  |-- Rollback Plan: {rollback}")
        if memory:
            logger.info(f"  |-- Memory: {memory}")
        if repo_instructions:
            logger.info(f"  |-- Repo Instructions: {repo_instructions}")

        # Run evaluation through classifier
        eval_output = evaluate_case(case, policy)
        
        req_dec = eval_output["requestDecision"]
        tool_dec = eval_output["toolDecision"]
        route = eval_output["route"]
        traj = eval_output["trajectory"]
        expl = eval_output.get("_explanation", {})

        # Tally counts
        counts["requestDecision"][req_dec] = counts["requestDecision"].get(req_dec, 0) + 1
        counts["toolDecision"][tool_dec] = counts["toolDecision"].get(tool_dec, 0) + 1
        counts["route"][route] = counts["route"].get(route, 0) + 1
        counts["trajectory"][traj] = counts["trajectory"].get(traj, 0) + 1

        logger.info("  |-- [DECISIONS]:")
        logger.info(f"       * requestDecision : {req_dec.upper()}  (Reasons: {', '.join(expl.get('requestReasons', [])) or 'None'})")
        logger.info(f"       * toolDecision    : {tool_dec.upper()}  (Reasons: {', '.join(expl.get('toolReasons', [])) or 'None'})")
        logger.info(f"       * route           : {route.upper()}  (Reasons: {', '.join(expl.get('routeReasons', [])) or 'None'})")
        logger.info(f"       * trajectory      : {traj.upper()}  (Reasons: {', '.join(expl.get('trajReasons', [])) or 'None'})")

        # Result item strictly formatted as required by specification
        result_item = {
            "caseId": case_id,
            "requestDecision": req_dec,
            "toolDecision": tool_dec,
            "route": route,
            "trajectory": traj
        }
        results.append(result_item)
        case_summaries.append({
            "caseId": case_id,
            "decisions": result_item,
            "explanation": expl,
            "userPrompt": user_msgs[-1] if user_msgs else "",
            "tool": proposed.get("name") if proposed else None
        })

    elapsed_ms = (time.time() - start_time) * 1000.0

    logger.info("=" * 80)
    logger.info(f"[BATCH COMPLETED] Batch {batch_id} in {elapsed_ms:.1f}ms")
    logger.info(f"   Summary Breakdown:")
    logger.info(f"   - requestDecision : {counts['requestDecision']}")
    logger.info(f"   - toolDecision    : {counts['toolDecision']}")
    logger.info(f"   - route           : {counts['route']}")
    logger.info(f"   - trajectory      : {counts['trajectory']}")
    logger.info("=" * 80)

    # Save to in-memory store for /logs web viewing
    batch_record = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "batchId": batch_id,
        "profile": profile,
        "casesCount": len(cases),
        "policy": policy,
        "counts": counts,
        "elapsedMs": elapsed_ms,
        "caseSummaries": case_summaries,
        "rawCases": cases
    }
    RECENT_BATCHES.insert(0, batch_record)
    if len(RECENT_BATCHES) > MAX_STORED_BATCHES:
        RECENT_BATCHES.pop()

    # Save to local file if possible
    try:
        filename = f"logs/batches/batch_{int(time.time())}_{batch_id}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump({
                "requestPayload": payload,
                "responsePayload": {
                    "profile": profile,
                    "batchId": batch_id,
                    "results": results
                },
                "caseSummaries": case_summaries
            }, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not persist batch to file: {e}")

    # Return standard grading response
    return {
        "profile": profile,
        "batchId": batch_id,
        "results": results
    }


# Handler for POST on root /
@app.post("/")
async def root_handler(request: Request):
    try:
        body = await request.json()
    except Exception as e:
        logger.error(f"Failed to parse JSON body: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    return process_harness_request(body)


# Catch-all handler for ANY other POST path
@app.post("/{full_path:path}")
async def catchall_post_handler(full_path: str, request: Request):
    logger.info(f"Handling POST request at custom route: /{full_path}")
    try:
        body = await request.json()
    except Exception as e:
        logger.error(f"Failed to parse JSON body: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    return process_harness_request(body)


# Inspection dashboard endpoint to easily browse received test cases in browser
@app.get("/logs", response_class=HTMLResponse)
async def view_logs():
    """Web interface to view detailed batch history, policies, and test case decisions."""
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Agent Harness Safety Layer - Logs</title>
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; margin: 20px; background: #0f172a; color: #f8fafc; }}
        h1, h2, h3 {{ color: #38bdf8; }}
        .batch-card {{ background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 24px; border: 1px solid #334155; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; margin-right: 5px; }}
        .badge-allow {{ background: #15803d; color: #fff; }}
        .badge-block {{ background: #b91c1c; color: #fff; }}
        .badge-review {{ background: #b45309; color: #fff; }}
        .badge-none {{ background: #475569; color: #fff; }}
        .badge-primary {{ background: #0284c7; color: #fff; }}
        .badge-restricted {{ background: #9333ea; color: #fff; }}
        .badge-normal {{ background: #059669; color: #fff; }}
        .badge-watch {{ background: #d97706; color: #fff; }}
        .badge-intervene {{ background: #dc2626; color: #fff; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }}
        th, td {{ border: 1px solid #334155; padding: 8px 12px; text-align: left; vertical-align: top; }}
        th {{ background: #0f172a; color: #94a3b8; }}
        pre {{ background: #020617; padding: 10px; border-radius: 6px; overflow-x: auto; color: #cbd5e1; font-size: 12px; }}
        details {{ margin-top: 10px; }}
        summary {{ cursor: pointer; color: #38bdf8; font-weight: 500; }}
      </style>
    </head>
    <body>
      <h1>🛡️ Agent Harness Safety & Routing Logs</h1>
      <p>Total Batches In Memory: <strong>{len(RECENT_BATCHES)}</strong></p>
    """
    
    if not RECENT_BATCHES:
        html += """
        <div class="batch-card">
          <p>⏳ No batches received yet. When you click <strong>Check</strong> or <strong>Save</strong> in your evaluation platform, incoming batches will appear here in real-time!</p>
        </div>
        """
    else:
        for b in RECENT_BATCHES:
            html += f"""
            <div class="batch-card">
              <h2>Batch: <code>{b['batchId']}</code> <span style="font-size:14px; color:#94a3b8;">({b['timestamp']}, {b['elapsedMs']:.1f}ms, {b['casesCount']} cases)</span></h2>
              <p>
                <strong>Decisions:</strong>
                Request: <code>{b['counts']['requestDecision']}</code> |
                Tool: <code>{b['counts']['toolDecision']}</code> |
                Route: <code>{b['counts']['route']}</code> |
                Trajectory: <code>{b['counts']['trajectory']}</code>
              </p>
              
              <details>
                <summary>📜 View Authoritative Policy</summary>
                <pre>{json.dumps(b['policy'], indent=2)}</pre>
              </details>

              <details open>
                <summary>📋 Cases & Classification Table ({len(b['caseSummaries'])})</summary>
                <table>
                  <tr>
                    <th>#</th>
                    <th>Case ID</th>
                    <th>User Prompt</th>
                    <th>Tool</th>
                    <th>requestDecision</th>
                    <th>toolDecision</th>
                    <th>route</th>
                    <th>trajectory</th>
                    <th>Reasons</th>
                  </tr>
            """
            for idx, c in enumerate(b["caseSummaries"], 1):
                d = c["decisions"]
                expl = c["explanation"]
                html += f"""
                  <tr>
                    <td>{idx}</td>
                    <td><code>{c['caseId'][:12]}...</code></td>
                    <td>{c['userPrompt'][:100]}</td>
                    <td><code>{c['tool'] or 'None'}</code></td>
                    <td><span class="badge badge-{d['requestDecision']}">{d['requestDecision']}</span></td>
                    <td><span class="badge badge-{d['toolDecision']}">{d['toolDecision']}</span></td>
                    <td><span class="badge badge-{d['route']}">{d['route']}</span></td>
                    <td><span class="badge badge-{d['trajectory']}">{d['trajectory']}</span></td>
                    <td><small>{'<br>'.join(expl.get('requestReasons', []) + expl.get('toolReasons', []))}</small></td>
                  </tr>
                """
            html += """
                </table>
              </details>
            </div>
            """

    html += """
    </body>
    </html>
    """
    return html


@app.get("/logs/json")
async def view_logs_json():
    """Returns raw JSON of all recent batches, policies, and decisions."""
    return {"batches": RECENT_BATCHES}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    logger.info(f"Starting server on 0.0.0.0:{port}")
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
