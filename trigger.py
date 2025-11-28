from fastapi import APIRouter, Request
from pydantic import BaseModel
from composio import Composio
from dotenv import load_dotenv
import uuid
load_dotenv()

composio = Composio()

def create_trigger(user_id: str, repo_owner: str, repo_name: str):
    """
    Creates a GitHub Pull Request event trigger for the specified repository.
    """
    trigger_type = composio.triggers.get_type("GITHUB_PULL_REQUEST_EVENT")
    trigger = composio.triggers.create(
        slug="GITHUB_PULL_REQUEST_EVENT",
        user_id=user_id,
        trigger_config={"owner": repo_owner, "repo": repo_name},
    )
    return trigger



router = APIRouter()

class TriggerRequest(BaseModel):
    repo_owner: str
    repo_name: str

@router.post("/create-trigger")
async def create_trigger_route(request: TriggerRequest):
    composio = Composio()
    user_id = "0000-0000-0004" 
    trigger = create_trigger(
        user_id=user_id,
        repo_owner=request.repo_owner,
        repo_name=request.repo_name
    )
    return {"message": "you have successfully made the pr review agent for your your repo"}

