# PR Review Agent

## Overview
This PR Review Agent automates the process of reviewing GitHub pull requests using agentic workflows and LLMs. It integrates with GitHub via Composio, analyzes code changes for security, scalability, and logic, and posts human-like review comments directly to PRs.

## Features
- **Webhook Integration:** Listens for GitHub PR events and triggers automated review workflows.
- **Agentic Analysis:** Uses LangGraph to orchestrate multiple agents for security, scalability, and logic analysis.
- **LLM-Powered Comments:** Generates meaningful, context-aware review comments using advanced language models.
- **Automated Review Posting:** Posts and submits review comments to GitHub PRs using Composio toolkit.
- **Trigger Management:** Easily set up PR event triggers for any repository.
- **Authentication Flow:** Supports OAuth authentication for secure GitHub access.

## How It Works
1. **Authentication:** Authenticate your GitHub account via the `/auth-url` route.
2. **Trigger Setup:** Use `/create-trigger` to set up PR event triggers for your repo.
3. **Webhook Handling:** The `/webhook` route receives PR events, extracts patch data, and runs agentic analysis.
4. **Review Generation:** Agents analyze the patch for security, scalability, and logic, then generate a summary comment.
5. **Review Submission:** The agent posts and submits the review comment to the PR, making it visible to contributors.

## API Endpoints
- `GET /auth-url` — Get the authentication URL for GitHub OAuth.
- `POST /create-trigger` — Set up a PR event trigger for your repository.
- `POST /webhook` — Handle incoming PR events and automate review.
- `GET /health` — Health check endpoint.

## Technologies Used
- **FastAPI** — API server and routing
- **LangGraph** — Agentic workflow orchestration
- **Composio** — GitHub API integration
- **Pydantic** — Data validation
- **Python** — Core language

## Setup & Usage
1. Clone the repository and install dependencies:
   ```bash
   git clone <repo-url>
   cd <project-folder>
   pip install -r requirements.txt
   ```
2. Start the FastAPI server:
   ```bash
   uvicorn main:app --reload
   ```
3. Authenticate your GitHub account via `/auth-url`.
4. Set up a trigger for your repo using `/create-trigger`.
5. Configure your GitHub webhook to point to `/webhook`.

## Example Workflow
1. Developer opens a PR in the repo.
2. GitHub sends a webhook event to `/webhook`.
3. The agent analyzes the patch and posts a review comment.
4. The review is submitted and visible on the PR page.

## License
MIT

## Maintainers
- TIGER-AI-Lab

---
For questions or support, open an issue or contact the maintainers.
