github_auth_config_id = "ac_qAtY4lK33LUK" 

from fastapi import APIRouter
from composio import Composio
from dotenv import load_dotenv
load_dotenv()


router = APIRouter()

github_auth_config_id = "ac_qAtY4lK33LUK"
user_id = "0000-0000-0008"
composio = Composio()

@router.get("/auth-url")
def get_auth_url():
    connection_request = composio.connected_accounts.initiate(
        user_id=user_id,
        auth_config_id=github_auth_config_id,
    )
    return {"auth_url": connection_request.redirect_url}
