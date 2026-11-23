# Agent Harness Safety Layer & Model Routing (2026-09)

This service implements the contextual safety and model routing layer for the agent harness evaluation benchmark.

## Architecture

1. **`classifier.py`**:
   - Classifies requests (`allow` / `block` / `review`)
   - Evaluates proposed tools against policy and environment isolation (`allow` / `block` / `review` / `none`)
   - Selects model routing (`primary` / `restricted` / `none`)
   - Tracks session trajectory and scope drift (`normal` / `watch` / `intervene`)
   - Defends against >10% unsafe approval penalty while maximizing Macro-F1 across all 4 axes.

2. **`server.py`**:
   - Built on FastAPI & Uvicorn.
   - Comprehensive structured logging per case.
   - Accepts POST at `/` and any custom route (`/{path}`).
   - Healthcheck at `GET /`.
   - Live visual log inspection dashboard at `GET /logs`.
   - Raw JSON batch data at `GET /logs/json`.

## Deploying to Render

1. **Push to GitHub**:
   ```bash
   git remote add origin https://github.com/<your-username>/<your-repo-name>.git
   git branch -M main
   git push -u origin main
   ```

2. **Create Web Service on Render**:
   - Go to [dashboard.render.com](https://dashboard.render.com/)
   - Click **New +** -> **Web Service**
   - Connect your repository
   - Set the following settings:
     - **Name**: `agent-harness-safety` (or your choice)
     - **Region**: Any (e.g. Oregon / Frankfurt / Singapore)
     - **Branch**: `main` (or `master`)
     - **Runtime**: `Python 3`
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `uvicorn server:app --host 0.0.0.0 --port $PORT`
     - **Instance Type**: Free
   - Click **Create Web Service**.

3. **Get your Public URL**:
   - Once deployed, Render provides: `https://agent-harness-safety-xxxx.onrender.com`
   - Paste this exact URL in the assessment input box:
     ```
     https://agent-harness-safety-xxxx.onrender.com/
     ```

4. **Real-time Monitoring & Logs**:
   - **Render Logs**: View live logs in the Render Dashboard under the "Logs" tab.
   - **Visual Dashboard**: Open `https://agent-harness-safety-xxxx.onrender.com/logs` in your browser to view all incoming batches, authoritative policies, and case-by-case decisions.
