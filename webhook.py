from fastapi import APIRouter, Request
import uvicorn
from pydantic import BaseModel
import requests
import uuid
from langgraph_sdk.client import get_client
import re
from composio import Composio
from verify_webhook import verify_webhook_signature

from dotenv import load_dotenv
load_dotenv()

composio = Composio(toolkit_versions={"github": "20251027_00"})
client = get_client(url = "http://localhost:2024")


router = APIRouter()
    
@router.post("/webhook")
async def webhook_handler(request: Request):
    # print("Webhook endpoint called")  # Entry point
    body = await request.body()
    diff_url = ""
    patch_url = ""
    commit_shaa = ""
    # print("Raw body received:", body)
    # print("Headers received:", dict(request.headers))
    
    auth_check = verify_webhook_signature(request, body)
    # print("Auth check result:", auth_check)
    if auth_check is None or auth_check is False:
        # print("Auth failed, returning early")
        return {"error": "auth failed (signature verification returned None or False)"}
    
    try:
        payload = await request.json()
        print(payload)
        pr_url = payload["data"]["url"]
        owner = pr_url.split("/")[3]
        repo = pr_url.split("/")[4]
        patch_url = pr_url + ".patch"
        pull_number = str(payload["data"]["number"])

        #get the the SHA
        txt = requests.get(patch_url).text
        commit_sha_match = re.search(r"^From ([0-9a-f]{40})", txt, re.MULTILINE)
        commit_sha = commit_sha_match.group(1) if commit_sha_match else None

    except Exception as e:
        print("Error parsing JSON:", e)
        return {"error": "invalid json"}

    
    thread_id = str(uuid.uuid4())
    print("Generated thread_id:", thread_id)
    
    try:
        thread = await client.threads.create(thread_id=thread_id)
        print("Thread created:", thread)
        # Pass a dict with 'pr_payload' key as expected by the LangGraph node
        run_input = {"pr_payload": {"patch_url": patch_url}}
        run = await client.runs.wait(assistant_id="agent", thread_id=thread_id, input=run_input)
        # print("Run result:", run)
        
        print("THINGS ARE WORKING")
        print(type(str(run["final_comment"]["content"])))
        print({
                "owner": owner,
                "repo": repo,
                "pull_number": pull_number,
                "body": str(run["final_comment"]["content"]),
                "path": run["parsed_patch"][0]["file"],
                "commit_id": commit_sha,
            })
        # Ensure body is a plain string
        comment_body = run["final_comment"]["content"]
        if not isinstance(comment_body, str):
            comment_body = str(comment_body)
        print("\n")
        print("=============================================")
        result = composio.tools.execute(
            "GITHUB_CREATE_A_REVIEW_FOR_A_PULL_REQUEST",
            user_id="0000-0000-0004",
            arguments={
                "owner": owner,
                "repo": repo,
                "pull_number": pull_number,
                "body": comment_body,
                "commit_id": commit_sha,
            }
        )
        print("result of the tool execution:", result)
        review_id = result["data"]["id"]

        submit_result = composio.tools.execute(
            "GITHUB_SUBMIT_A_REVIEW_FOR_A_PULL_REQUEST",
            user_id="0000-0000-0004",
            arguments={
                "owner": owner,
                "repo": repo,
                "pull_number": pull_number,
                "review_id": review_id,
                "event": "COMMENT"
            }
        )
        print("\n")
        print("submit request \n")
        print(submit_result)
        
    except Exception as e:
        print("Error in LangGraph client:", e)
        return {"error": "langgraph client error"}
    
    return {"message": "the comment has been successfully made on the PR"}


