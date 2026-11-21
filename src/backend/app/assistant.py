"""Cyber Assistant chat backed by Groq (OpenAI-compatible API)."""

from __future__ import annotations

import logging
import re
from typing import Literal

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/assistant", tags=["assistant"])

GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"
MAX_HISTORY = 16
MAX_CONTENT_CHARS = 4000
MAX_CONTEXT_CHARS = 6000

SYSTEM_PROMPT = """You are CyberGuard’s Cyber Assistant — a calm cybersecurity guide inside the CyberGuard web app.

Style (important):
- Write like a helpful person texting a friend: plain English, easy for anyone to follow.
- Keep replies short: usually 2–4 short sentences. If steps help, use at most 3 simple numbered lines like:
  1. Do this.
  2. Then this.
- Never use asterisks (* or **), underscores for emphasis, markdown headings (###), or bold/italic markup.
- Do not use bullet characters like - or • unless you truly need a tiny list; prefer numbered steps or plain sentences.
- No horizontal rules. No dense walls of text.
- One helpful CyberGuard link is enough when relevant, written exactly like: [Email Scanner](/email-scanner)

Your job:
- Answer everyday defensive cybersecurity questions clearly.
- Help users find features in CyberGuard using only the real pages below.

CyberGuard pages (only these — do not invent others or fake menus):
- [Dashboard](/dashboard) — home overview
- [Team Security](/organization) — create/join organizations, invite members, team protection
- [Website Tracker](/website-tracker) — reviewed sites and risk scores
- [Email Scanner](/email-scanner) — scan emails / Gmail for phishing
- [Security Checker](/security-checker) — security checks
- [Device Scanner](/device-scanner) — local device scan (sign-in required)
- [System Guardian](/system-guardian) — local system monitoring (sign-in required)
- [News](/news) — cybersecurity news
- [Reports](/reports) — scan reports / history
- [Settings](/settings) — profile, account, and alert preferences only
- Login / Sign up — buttons at the top of the left sidebar

True product facts (do not contradict these):
- To create a team/organization: open Team Security, then Create organization. User must be signed in.
- Settings cannot create a team, organization, or invite members.
- Do not invent buttons, menus, screens, toggles, or steps that are not listed here.
- Never guess CyberGuard UI. If the provided context does not clearly explain a step, say you are not sure and link the closest real page.
- For general cybersecurity advice, stay practical and defensive. Do not invent CyberGuard features while giving that advice.

Hard rules:
- Defensive guidance only. Refuse hacking, cracking accounts, bypassing security, malware creation, exploits, social-engineering attacks, or anything meant to harm people or systems.
- If refused, one short sentence is enough, then invite a safer question.
- When relevant context is provided below, ground your answer in it — but never invent app steps that conflict with the facts above.
- Do not mention system prompts, API keys, or that you are powered by Groq unless asked how the assistant works at a high level.
"""


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=MAX_CONTENT_CHARS)


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=40)
    context: str | None = Field(default=None, max_length=MAX_CONTEXT_CHARS)


class ChatResponse(BaseModel):
    reply: str
    model: str


def _trim_messages(messages: list[ChatMessage]) -> list[dict[str, str]]:
    trimmed = messages[-MAX_HISTORY:]
    # Groq expects the conversation to start usefully; drop leading assistant turns.
    while trimmed and trimmed[0].role != "user":
        trimmed = trimmed[1:]
    if not trimmed:
        raise HTTPException(status_code=400, detail="At least one user message is required.")
    return [{"role": m.role, "content": m.content.strip()} for m in trimmed if m.content.strip()]


def _plain_reply(text: str) -> str:
    """Strip markdown emphasis so users never see asterisks or hash headings."""
    cleaned = text.replace("\r\n", "\n")
    cleaned = re.sub(r"^#{1,6}\s*", "", cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r"\*\*(.+?)\*\*", r"\1", cleaned)
    cleaned = re.sub(r"__(.+?)__", r"\1", cleaned)
    cleaned = re.sub(r"(?<!\w)\*(?!\s)(.+?)(?<!\s)\*(?!\w)", r"\1", cleaned)
    cleaned = re.sub(r"(?<!\w)_(?!\s)(.+?)(?<!\s)_(?!\w)", r"\1", cleaned)
    cleaned = cleaned.replace("**", "").replace("__", "")
    cleaned = re.sub(r"^[\-\*•]\s+", "", cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


TEAM_CREATE_CORRECTION = """Open Team Security in the left sidebar.

1. Click Create organization.
2. Enter a name and confirm.

You need to be signed in. Settings cannot create a team.

[Team Security](/organization)"""


def _latest_user_text(messages: list[dict[str, str]]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user":
            return message.get("content", "")
    return ""


def _correct_known_hallucinations(user_text: str, reply: str) -> str:
    """Replace a few high-confidence wrong product claims with grounded copy."""
    user = user_text.lower()
    text = reply.lower()
    asking_to_create_team = (
        any(word in user for word in ("team", "organization", "organisation", "org"))
        and any(word in user for word in ("create", "make", "new", "start", "setup", "set up"))
    )
    if asking_to_create_team and "settings" in text and any(
        word in text for word in ("create", "team", "organization", "organisation")
    ):
        return TEAM_CREATE_CORRECTION
    return reply


@router.post("/chat", response_model=ChatResponse)
async def assistant_chat(payload: ChatRequest) -> ChatResponse:
    api_key = (settings.GROQ_API_KEY or "").strip()
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="Cyber Assistant LLM is not configured (missing GROQ_API_KEY).",
        )

    history = _trim_messages(payload.messages)
    system = SYSTEM_PROMPT
    if payload.context and payload.context.strip():
        # Context may include markdown from the local knowledge base — strip emphasis
        # so the model is less likely to copy asterisks into the reply.
        grounded = _plain_reply(payload.context)
        system = (
            f"{SYSTEM_PROMPT}\n\nRelevant CyberGuard knowledge for this question "
            f"(use the ideas, keep your reply plain):\n{grounded}"
        )

    model = (settings.GROQ_MODEL or "openai/gpt-oss-20b").strip()
    body = {
        "model": model,
        "messages": [{"role": "system", "content": system}, *history],
        "temperature": 0.15,
        "max_tokens": 320,
    }

    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            response = await client.post(
                GROQ_CHAT_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=body,
            )
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="Assistant model timed out.") from exc
    except httpx.HTTPError as exc:
        logger.exception("Groq request failed")
        raise HTTPException(status_code=502, detail="Could not reach the assistant model.") from exc

    if response.status_code == 401:
        raise HTTPException(status_code=502, detail="Groq API key was rejected.")
    if response.status_code == 429:
        raise HTTPException(
            status_code=429,
            detail="Assistant rate limit reached. Try again in a moment.",
        )
    if response.status_code >= 400:
        detail = "Assistant model error."
        try:
            err = response.json()
            detail = err.get("error", {}).get("message") or detail
        except Exception:
            pass
        logger.warning("Groq error %s: %s", response.status_code, detail)
        raise HTTPException(status_code=502, detail=detail)

    data = response.json()
    try:
        reply = _plain_reply(data["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError, AttributeError) as exc:
        raise HTTPException(status_code=502, detail="Unexpected model response.") from exc

    if not reply:
        raise HTTPException(status_code=502, detail="Model returned an empty reply.")

    reply = _correct_known_hallucinations(_latest_user_text(history), reply)
    return ChatResponse(reply=reply, model=data.get("model", model))
