from typing_extensions import TypedDict
from typing import Any, Dict, List, Literal, Optional, Annotated

from langgraph.graph import StateGraph
from langgraph.graph.message import add_messages
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode, tools_condition

from langchain.chat_models import init_chat_model
from langchain_core.messages import AIMessage
from pydantic import BaseModel
from typing import List
import json

llm = init_chat_model("openai:gpt-4.1")

import requests
from unidiff import PatchSet

class PRPayload(TypedDict):
    patch_url: str
    
class Change(TypedDict):
    file: str
    type: str
    line: str
    lineno: int

class FileDiff(TypedDict):
    file: str
    original_code: str
    modified_code: str
    changes: List[Change]

class ParsedPatch(TypedDict):
    files: List[FileDiff]
    
Severity = Literal["low", "medium", "high", "critical"]

class SecurityIssue(TypedDict):
    file: str
    line: int
    severity: Severity
    title: str
    description: str
    suggested_fix: str

class SecurityReport(TypedDict):
    issues: Optional[List[SecurityIssue]]
    overall_security_score: float   # 0.0 to 1.0


class ScalabilityIssue(TypedDict):
    file: str
    line: int
    severity: Severity
    message: str   # combined title + description
    fix: str       # suggested fix

class ScalabilityReport(TypedDict):
    issues: Optional[List[ScalabilityIssue]]   # optional or null
    score: float    
    

class LogicIssue(TypedDict):
    file: str
    line: int
    severity: Severity
    message: str   # describes the logic flaw
    fix: str       # suggested correction

class LogicReport(TypedDict, total=False):
    issues: Optional[List[LogicIssue]]   # optional / None / omitted if perfect
    score: float       
    
    
class State(TypedDict):
    messages:  Annotated[list, add_messages]
    pr_payload: PRPayload
    parsed_patch: ParsedPatch
    security_report: SecurityReport
    scalability_report: ScalabilityReport
    logic_report: LogicReport
    final_comment: str


def extract_patch_with_full_files(state: State) -> ParsedPatch:
    """
    Fetches a .patch from a URL, parses it, reconstructs original and modified code,
    and returns a per-file diff with full text.
    """
    url = state["pr_payload"]["patch_url"]
    # 1. Fetch patch text
    resp = requests.get(url)
    if resp.status_code != 200:
        raise RuntimeError(f"Failed to fetch patch: HTTP {resp.status_code}")
    patch_text = resp.text

    # 2. Parse using unidiff
    patch = PatchSet(patch_text)

    parsed_files: List[FileDiff] = []

    # 3. Iterate files
    for f in patch:
        file_path = f.path or f.target_file or f.source_file

        original_lines: List[str] = []
        modified_lines: List[str] = []
        changes: List[Change] = []

        # reconstruct code by replaying hunks
        for hunk in f:
            old_ln = hunk.source_start
            new_ln = hunk.target_start

            for line in hunk:
                content = line.value.rstrip("\n")

                if line.is_added:
                    # present only in modified file
                    modified_lines.append(content)
                    changes.append({
                        "file": file_path,
                        "type": "added",
                        "line": content,
                        "lineno": line.target_line_no
                    })
                    new_ln += 1

                elif line.is_removed:
                    # present only in original file
                    original_lines.append(content)
                    changes.append({
                        "file": file_path,
                        "type": "removed",
                        "line": content,
                        "lineno": line.source_line_no
                    })
                    old_ln += 1

                else:
                    # context line: present in both
                    original_lines.append(content)
                    modified_lines.append(content)
                    old_ln += 1
                    new_ln += 1

        parsed_files.append({
            "file": file_path,
            "original_code": "\n".join(original_lines),
            "modified_code": "\n".join(modified_lines),
            "changes": changes
        })

    return {"parsed_patch": parsed_files}



#SECURITY AGENT ------------------------------
def security_agent(state: State):
    prompt = """
    You are a Security Analysis Agent. Your job is to analyze code changes and detect ANY security-relevant issues.
    Your input is always a structured payload.

    You must identify security problems using static analysis and reasoning.
    You MUST examine both original and modified versions of code and focus primarily on the changed lines.


    ## YOUR RESPONSIBILITIES
    Detect the following categories of vulnerabilities (non-exhaustive):

    ### 1. Secrets & Credential Exposure
    - Hardcoded API keys, tokens, JWTs, passwords, OAuth secrets
    - Cloud credentials (AWS, GCP, Azure)
    - High-entropy strings that look like secrets
    - Private keys, PEM blocks

    ### 2. Injection Attacks
    - SQL injection (string concatenation with queries, unsafe parameters)
    - Command injection (passing user-controlled input to exec/spawn/sh)
    - OS injection
    - LDAP injection
    - Template injection

    ### 3. Web Security Issues
    - Cross-Site Scripting (XSS)
    - DOM-based XSS
    - Insecure innerHTML assignments
    - Unsafe DOM parsing
    - Open Redirects

    ### 4. Server Security Issues
    - Path traversal (`../`)
    - SSRF (fetching URLs based on user input)
    - Insecure file reads/writes
    - Deserialization vulnerabilities
    - Unsafe yaml/json/pickle loads

    ### 5. Cryptographic Issues
    - Weak hashing (md5, sha1)
    - Hardcoded encryption keys/IVs
    - Non-random salts
    - ECB mode
    - Rolling your own crypto

    ### 6. Dangerous Functions / Patterns
    - `eval`, `Function()`, `exec`, `pickle.loads`, `yaml.load`
    - `child_process.exec` with untrusted input
    - Disabled certificate validation
    - CORS misconfigurations

    ### 7. Dependency-Level Problems (Lightweight)
    When dependency files (package.json, requirements.txt) change:
    - Check for known dangerous libs
    - Check if unsafe versions are being introduced (best-effort heuristic)

    ### 8. Configuration Issues
    - Debug flags enabled in production paths
    - Open CORS (`*`)
    - Missing authentication checks in newly added code


    ## HOW TO THINK
    - Focus attention on **changed lines**, then use surrounding context to confirm.
    - Reason about how user input flows into functions.
    - Explain **why** something is dangerous.
    - If something looks safe, explicitly say you verified it.

    Rules for scoring:
    - Start from 1.0 (perfect security)
    - Subtract:
    - 0.6 for critical findings
    - 0.4 for high
    - 0.2 for medium
    - 0.05 for low
    - Minimum score: 0.0

    If **no issues**, score must be **1.0**.

    ## NEGATIVE OR BAD EXAMPLES
    
    ### Example 1: Secret exposed
    BAD:
    const apiKey = "AIzaSyCk1v....";

    This is a leaked credential. Secrets must not exist in source.

    ### Example 2: SQL Injection
    BAD:
    const q = "SELECT * FROM users WHERE id=" + userInput;

    User-controlled input gets concatenated into a SQL query.

    ### Example 3: Dangerous eval
    BAD:
    eval(userProvidedCode);

    Arbitrary execution → remote code execution.

    ### Example 4: XSS
    BAD:
    element.innerHTML = request.body.text;

    User text inserted directly into DOM.

    ### Example 5: Path traversal
    readFile("../" + userInput + "/config");

    User can escape directories.

    ------------------------------------------------------------
    ## FEW-SHOT GOOD CODE EXAMPLES

    GOOD:
    const stmt = db.prepare("SELECT * FROM users WHERE id = ?");
    stmt.bind(userInput);

    GOOD:
    element.textContent = safeValue;

    GOOD:
    if (!authUser) return res.status(401).send("unauthorized");

    GOOD:
    crypto.createHmac("sha256", secretKey);

    ------------------------------------------------------------
    ## FINAL INSTRUCTION
    You must:
    1. Detect all meaningful vulnerabilities.
    2. Ignore harmless lines and avoid false positives.
    3. Output clean JSON strictly following the schema.
    4. Always include an overall security score from 0 to 1.
    """
    
    structured_llm = llm.with_structured_output(SecurityReport)
    response = structured_llm.invoke([
        {"role": "system", "content": prompt}, {"role": "user", "content": json.dumps(state["parsed_patch" ])}
    ])

    ai_msg = AIMessage(
        content=f"The security check has been completed successfully"
    )
    
    return {
        "messages": [ai_msg],
        "security_report": response
    }

#SCALABILITY AGENT ------------------------------
def scalability_agent(state: State):
    prompt = """
    You are a Scalability and Readability Analysis Agent. Your job is to analyze code changes and detect any scalability or readability-relevant issues.
    Your input is a structured payload containing code diffs and context.

    ## SCALABILITY RESPONSIBILITIES
    Detect issues such as:
    - Inefficient algorithms (e.g., nested loops, poor data structures)
    - Resource bottlenecks (unbounded memory, inefficient I/O)
    - Concurrency issues (blocking ops, lack of parallelism)
    - Database scalability (N+1 queries, unindexed queries)
    - Hardcoded limits (fixed-size buffers, arbitrary limits)
    - Poor caching (missing or inefficient caching)

    ## READABILITY RESPONSIBILITIES
    Detect issues such as:
    - Overly complex or deeply nested code
    - Poor variable/function naming
    - Lack of comments or documentation
    - Large functions doing too much

    ## BAD EXAMPLES

    ### Scalability
    BAD:
    for i in range(n):
        for j in range(n):
            for k in range(n):
                process(data[i][j][k])
    # O(n^3) time complexity, not scalable for large n

    BAD:
    results = []
    for item in items:
        results.append(fetch_from_db(item))
    # N+1 query problem, inefficient for large lists

    BAD:
    buffer = []
    while True:
        buffer.append(get_data())
    # Unbounded memory usage, can cause crashes

    ### Readability
    BAD:
    def a(x):
        return x*x
    # Poor function naming, unclear purpose

    BAD:
    def process(data):
        # no comments, does too much
        ...

    BAD:
    if x:
        if y:
            if z:
                do_something()
    # Deeply nested code, hard to read

    ## HOW TO THINK
    - Focus on changed lines, then use context to confirm.
    - Reason about how code will behave with large inputs or high load.
    - Explain why something is a scalability or readability concern.
    - If something looks scalable and readable, explicitly say you verified it.

    ## SCORING
    - Start from 1.0 (perfect scalability/readability)
    - Subtract:
        - 0.6 for critical findings
        - 0.4 for high
        - 0.2 for medium
        - 0.05 for low
    - Minimum score: 0.0
    - If no issues, score must be 1.0.

    ## FINAL INSTRUCTION
    You must:
    1. Detect all meaningful scalability and readability issues.
    2. Ignore harmless lines and avoid false positives.
    3. Output clean JSON strictly following the schema.
    4. Always include an overall scalability score from 0 to 1.
    """
    
    # Use the same output schema as SecurityReport for simplicity
    structured_llm = llm.with_structured_output(ScalabilityReport)
    response = structured_llm.invoke([
        {"role": "system", "content": prompt}, {"role": "user", "content": json.dumps(state["parsed_patch"])}
    ])

    ai_msg = AIMessage(
        content=f"The scalability check has been completed successfully"
    )
    
    return {
        "messages": [ai_msg],
        "scalability_report": response
    }


def logic_agent(state: State):
    prompt = """
    You are a Logic Analysis Agent. Your job is to analyze code changes and detect any logic-relevant issues.
    Your input is a structured payload containing code diffs and context.

    ## LOGIC RESPONSIBILITIES
    Detect issues such as:
    - Logical errors (off-by-one, incorrect conditions, wrong return values)
    - Edge cases not handled (empty lists, None/null, zero, negative numbers)
    - Incorrect use of control flow (break/continue, early returns)
    - Misuse of APIs or libraries
    - Unreachable code
    - Dead code or redundant logic

    ## BAD EXAMPLES

    BAD:
    for i in range(len(arr)):
        arr[i+1] = arr[i]  # Off-by-one error, may cause IndexError

    BAD:
    if x > 0:
        do_something()
    # Fails to handle x == 0 or x < 0

    BAD:
    def divide(a, b):
        return a / b
    # No check for b == 0, division by zero error

    BAD:
    if flag:
        return True
    else:
        return True
    # Redundant logic, always returns True

    BAD:
    def process(data):
        if data is not None:
            pass
        # Unreachable code below
        print("Done")

    ## HOW TO THINK
    - Focus on changed lines, then use context to confirm.
    - Reason about edge cases and logical correctness.
    - Explain why something is a logic concern.
    - If something looks logically correct, explicitly say you verified it.

    ## SCORING
    - Start from 1.0 (perfect logic)
    - Subtract:
        - 0.6 for critical findings
        - 0.4 for high
        - 0.2 for medium
        - 0.05 for low
    - Minimum score: 0.0
    - If no issues, score must be 1.0.

    ## FINAL INSTRUCTION
    You must:
    1. Detect all meaningful logic issues.
    2. Ignore harmless lines and avoid false positives.
    3. Output clean JSON strictly following the schema.
    4. Always include an overall logic score from 0 to 1.
    """
    structured_llm = llm.with_structured_output(LogicReport)
    response = structured_llm.invoke([
        {"role": "system", "content": prompt}, {"role": "user", "content": json.dumps(state["parsed_patch"])}
    ])

    ai_msg = AIMessage(
        content=f"The logic check has been completed successfully"
    )
    return {
        "messages": [ai_msg],
        "logic_report": response
    }
    
# FINAL AGENT ------------------------------
def final_agent(state: State):
    prompt = """
    You are a senior code reviewer. Based on the following analysis reports (security, scalability, logic), write a meaningful, balanced comment for the PR. Your comment should:
    - Summarize key findings from each analysis
    - Highlight strengths and areas for improvement
    - Be constructive, actionable, and professional
    - Not be too short or too verbose (aim for 5-10 sentences)
    - Mimic the style of a thoughtful human reviewer

    ## Example structure:
    - Brief summary of the PR and its changes
    - Security findings (mention any issues or confirm good practices)
    - Scalability findings (mention any concerns or confirm efficiency)
    - Logic findings (mention correctness, edge cases, or improvements)
    - Overall impression and recommendations

    ## Input:
    - Security report: {security_report}
    - Scalability report: {scalability_report}
    - Logic report: {logic_report}
    """.format(
        security_report=json.dumps(state.get("security_report", {})),
        scalability_report=json.dumps(state.get("scalability_report", {})),
        logic_report=json.dumps(state.get("logic_report", {}))
    )

    structured_llm = llm
    response = structured_llm.invoke([
        {"role": "system", "content": prompt}
    ])

    ai_msg = AIMessage(
        content="the final agent has been completed successfully"
    )
    return {
        "messages": [ai_msg],
        "final_comment": response
    }

agent_graph = StateGraph(State)
agent_graph.add_node(extract_patch_with_full_files)
agent_graph.add_node(security_agent)
agent_graph.add_node(scalability_agent)

agent_graph.add_node(logic_agent)
agent_graph.add_node(final_agent)


agent_graph.add_edge(START, "extract_patch_with_full_files")
agent_graph.add_edge("extract_patch_with_full_files", "security_agent")

agent_graph.add_edge("security_agent", "scalability_agent")

agent_graph.add_edge("scalability_agent", "logic_agent")

agent_graph.add_edge("logic_agent", "final_agent")
agent_graph.add_edge("final_agent", END)

app = agent_graph.compile()
