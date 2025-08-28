import os
import logging
import asyncio
import uuid
import re
import json
import random
from typing import Dict
from fastapi import FastAPI, File, UploadFile, Request, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.responses import StreamingResponse
from starlette.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from openai import AzureOpenAI
import fitz  # PyMuPDF
from dotenv import load_dotenv # ### FIX 1: ADDED for local testing

# Import the new DOCX report generator
from .report_generator import create_docx_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
load_dotenv() # ### FIX 2: ADDED to load .env file for local testing

# --- Application State and Configuration ---
jobs: Dict[str, Dict] = {}

PROMPT_TEMPLATE = """
You are an expert security analyst AI. Your task is to analyze the following consolidated application security scan reports (which may include Mend, Fortify, Contrast, SonarQube, or similar tools). Your analysis must be comprehensive, actionable, and tailored for both technical and business stakeholders.
Your assessment should be structured, data-driven, and visually engaging, using tables and graphs where possible. Draw clear, evidence-based conclusions and avoid generic or random recommendations.

INPUT:

Consolidated scan report content from up to four sources (at least one is mandatory).


OUTPUT REQUIREMENTS:
1. EXECUTIVE SUMMARY

Provide a concise overview of the application’s security posture.
Highlight key risk indicators and trends observed across all scans.
Assign an overall security score or rating (with justification).
Summarize the most critical risks in a business-relevant manner.

2. DETAILED FINDINGS

List and describe all critical vulnerabilities, including their potential impact and exploitability.
Summarize medium and low severity issues, grouping by type and frequency.
Identify recurring patterns or systemic weaknesses across scans.
Flag likely false positives, explaining the rationale.
Use tables to present vulnerabilities by severity, type, and affected components.
Where possible, include graphs (e.g., bar charts for vulnerability counts, pie charts for severity distribution).

3. RISK ASSESSMENT

Present a risk prioritization matrix (e.g., heatmap or table) mapping vulnerabilities by likelihood and impact.
Analyze potential business impacts (e.g., data breach, compliance failure, operational disruption).
Discuss compliance implications (e.g., OWASP Top 10, PCI DSS, GDPR) and highlight any gaps.

4. RECOMMENDATIONS

Provide immediate actions for critical issues (with clear steps).
Outline a short-term remediation plan for high and medium risks.
Suggest long-term improvements to strengthen security posture (e.g., process, tooling, training).
Recommend best practices tailored to the observed issues and technology stack.
Ensure all recommendations are specific, actionable, and prioritized by risk and business impact.

5. METRICS, TRENDS & VISUALIZATIONS

Present key metrics:

Vulnerability counts by severity, type, and affected modules.
Trends over time (if historical data is present).
Comparison across different scan tools (highlighting discrepancies or tool-specific findings).


Use visualizations (tables, bar/pie charts, trend lines) to make data easily digestible.
Highlight any positive trends or improvements compared to previous scans (if data available).

6. CONCLUSION & NEXT STEPS

Summarize the top 3 actionable insights.
Recommend next steps for both technical and business teams.
Suggest follow-up assessments or monitoring if needed.


ADDITIONAL INSTRUCTIONS:

Base all conclusions and recommendations strictly on the data provided. Do not generate generic or random suggestions.
Cite specific evidence from the reports to support your findings.
Use clear, professional language suitable for both technical and executive audiences.
Where visualizations are suggested, describe them in Markdown (e.g., tables, chart descriptions) so they can be rendered or created by downstream tools.
If any required data is missing, clearly state the limitation and its impact on the analysis.


INPUT DATA:
{consolidated_content}
Begin your analysis below:
"""


# --- FastAPI App Initialization ---
app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# --- Azure OpenAI Client Setup ---
try:
    azure_endpoint = str(os.getenv("AZURE_OPENAI_ENDPOINT"))
    api_key = str(os.getenv("AZURE_OPENAI_API_KEY"))
    deployment_name = str(os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME"))
    # ### FIX 3: REVERTED TO A VALID AND ROBUST API VERSION STRING ###
    api_version = str(os.getenv("API_VERSION", "2023-12-01-preview"))

    if not all([azure_endpoint, api_key, deployment_name]):
        raise ValueError("FATAL: One or more required Azure OpenAI environment variables are missing.")

    client = AzureOpenAI(api_key=api_key, api_version=api_version, azure_endpoint=azure_endpoint)
    logging.info(f"Azure OpenAI client configured successfully for deployment '{deployment_name}'.")
except Exception as e:
    logging.error(f"Failed to initialize application: {e}", exc_info=True)
    exit()

# --- Utility Functions (Compliant Versions) ---
def count_tokens(text: str) -> int:
    """A simple, dependency-free token counter."""
    # A slightly better approximation than just split()
    return len(text) // 4

BASE_PROMPT_TOKENS = count_tokens(PROMPT_TEMPLATE.format(consolidated_content=""))

async def get_text_from_file(file: UploadFile) -> str:
    """Extracts text from an uploaded file (PDF or plain text)."""
    text_content = ""
    file_bytes = await file.read()
    if file.filename and file.filename.lower().endswith('.pdf'):
        try:
            with fitz.open(stream=file_bytes, filetype="pdf") as doc:
                text_content = "".join(page.get_text() for page in doc)# type: ignore
        except Exception as e:
            logging.error(f"PyMuPDF failed to process '{file.filename}': {e}")
    else:
        text_content = file_bytes.decode("utf-8", errors="ignore")
    return text_content

async def run_openai_with_retry(prompt: str, max_attempts: int = 3) -> str:
    """Runs OpenAI completion with a manual, dependency-free retry loop."""
    for attempt in range(max_attempts):
        try:
            response = await asyncio.to_thread(
                lambda: client.chat.completions.create(
                    model=deployment_name,
                    messages=[{"role": "user", "content": prompt}]
                )
            )
            content = response.choices[0].message.content
            return content if content else ""
        except Exception as e:
            if attempt == max_attempts - 1:
                logging.error(f"OpenAI call failed after {max_attempts} attempts. Error: {e}")
                raise
            wait_time = (2 ** attempt) + random.uniform(0, 1)
            logging.warning(f"OpenAI call failed (attempt {attempt + 1}/{max_attempts}). Retrying in {wait_time:.2f}s...")
            await asyncio.sleep(wait_time)
    return ""

# --- Background Task for Report Processing ---
async def process_report_task(job_id: str):
    job = jobs[job_id]
    def update_status(message: str, message_type: str = "status"):
        job["status_updates"].append({"type": message_type, "content": message})
    
    try:
        update_status("Starting consolidation process. Summarizing individual files...")
        all_summaries = []
        for file_info in job["files"]:
            filename = file_info['filename']
            content_str = file_info['content']
            update_status(f"Summarizing file: {filename}...")
            
            summary_prompt = f"Summarize all critical vulnerabilities from the file '{filename}'. TEXT: {content_str}"
            summary = await run_openai_with_retry(summary_prompt)
            all_summaries.append(f"--- Summary from {filename} ---\n{summary}")
            
            await asyncio.sleep(5)

        update_status("All summaries created. Generating final consolidated report...")
        consolidated_summaries = "\n\n".join(all_summaries)
        final_prompt = PROMPT_TEMPLATE.format(consolidated_content=consolidated_summaries)
        
        # ### FIX 4: ADDED ENHANCED LOGGING BEFORE THE FINAL CALL ###
        final_token_count = count_tokens(final_prompt)
        update_status(f"Final prompt created with ~{final_token_count:,} tokens. Sending to OpenAI...")
        logging.info(f"Job {job_id}: Sending final prompt with {final_token_count} tokens.")

        report_markdown = await run_openai_with_retry(final_prompt, max_attempts=5)
        
        if not report_markdown:
            raise ValueError("The AI returned an empty response. This can be caused by content filters.")

        job["report_content"] = report_markdown
        update_status("Report content generated.", "report")
        logging.info(f"Job {job_id}: Successfully generated report.")
    except Exception as e:
        # ### FIX 5: ADDED DETAILED EXCEPTION LOGGING TO SEE THE REAL ERROR ###
        error_message = f"An error occurred during report processing: {e}"
        logging.error(f"Job {job_id}: {error_message}", exc_info=True)
        update_status(error_message, "error")
    finally:
        job["is_complete"] = True

# --- API Endpoints ---
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/config")
async def get_config():
    return JSONResponse({"base_prompt_tokens": BASE_PROMPT_TOKENS})

@app.post("/count-tokens")
async def count_tokens_endpoint(file: UploadFile = File(...)):
    text = await get_text_from_file(file)
    token_count = count_tokens(text)
    return JSONResponse({"token_count": token_count})

@app.post("/upload")
async def upload_files_for_processing(background_tasks: BackgroundTasks, file1: UploadFile=File(None), file2: UploadFile=File(None), file3: UploadFile=File(None), file4: UploadFile=File(None)):
    files = [f for f in [file1, file2, file3, file4] if f and f.filename]
    if not files:
        raise HTTPException(status_code=400, detail="No files were uploaded.")

    file_contents = [{"filename": f.filename, "content": await get_text_from_file(f)} for f in files]
    
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"files": file_contents, "status_updates": [], "is_complete": False, "report_content": None}
    background_tasks.add_task(process_report_task, job_id)
    return JSONResponse({"job_id": job_id})

@app.get("/download/{job_id}")
async def download_report(job_id: str):
    if job_id not in jobs or not jobs[job_id].get("report_content"):
        raise HTTPException(status_code=404, detail="Report not found or not yet complete.")

    report_markdown = jobs[job_id]["report_content"]
    docx_bytes = create_docx_report(report_markdown)

    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f"attachment; filename=consolidated_security_report_{job_id[:8]}.docx"}
    )

@app.get("/stream/{job_id}")
async def stream_status(request: Request, job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job ID not found.")
    
    async def event_generator():
        last_sent_index = 0
        while True:
            if await request.is_disconnected():
                break
            
            job = jobs[job_id]
            if last_sent_index < len(job["status_updates"]):
                for update in job["status_updates"][last_sent_index:]:
                    yield f"data: {json.dumps(update)}\n\n"
                last_sent_index = len(job["status_updates"])
            
            if job["is_complete"]:
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                break
            
            await asyncio.sleep(1)
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")