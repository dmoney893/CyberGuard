import { API_BASE } from "../../api/emailApi";
import { OUT_OF_SCOPE_REPLY } from "./knowledgeBase";
import { localGuidedProvider } from "./localGuidedProvider";
import {
  buildAssistantContext,
  isProductQuestion,
} from "./retrieveContext";
import type { AssistantMessage, AssistantReplyProvider } from "./types";

/** Phrases that indicate the user wants attack/abuse help — refuse locally. */
const OFFENSIVE_PATTERNS = [
  /\bhow (do|can|to) (i|you) hack\b/i,
  /\bhack (into|someone|an? account)\b/i,
  /\bcrack (a |the )?password\b/i,
  /\bsteal (passwords?|accounts?|data)\b/i,
  /\bbypass (2fa|mfa|authentication|security|login)\b/i,
  /\bmake (a )?virus\b/i,
  /\bcreate (malware|ransomware)\b/i,
  /\bdos attack\b/i,
  /\bddos\b/i,
  /\bsql injection\b/i,
  /\bkeylogger\b/i,
  /\bbrute ?force\b/i,
];

/** Known wrong app claims the model has made before. */
const HALLUCINATION_CHECKS: Array<{
  test: (userText: string, reply: string) => boolean;
  correction: string;
}> = [
  {
    test: (userText, reply) => {
      const user = userText.toLowerCase();
      const aboutTeam =
        /\b(team|organization|organisation|org)\b/.test(user) &&
        /\b(create|make|new|start|set up|setup)\b/.test(user);
      if (!aboutTeam) {
        return false;
      }
      return (
        /\bsettings\b/.test(reply.toLowerCase()) &&
        /\b(create|team|organization|organisation)\b/.test(reply.toLowerCase())
      );
    },
    correction: `Open Team Security in the left sidebar.

1. Click Create organization.
2. Enter a name and confirm.

You need to be signed in. Settings cannot create a team.

[Team Security](/organization)`,
  },
];

function lastUserContent(messages: AssistantMessage[]): string {
  return (
    [...messages].reverse().find((message) => message.role === "user")
      ?.content ?? ""
  );
}

function isOffensiveRequest(text: string): boolean {
  return OFFENSIVE_PATTERNS.some((pattern) => pattern.test(text));
}

function correctHallucinations(userText: string, reply: string): string {
  for (const check of HALLUCINATION_CHECKS) {
    if (check.test(userText, reply)) {
      return check.correction;
    }
  }
  return reply;
}

async function fetchGenerativeReply(
  messages: AssistantMessage[],
): Promise<string> {
  const userText = lastUserContent(messages);
  const context = buildAssistantContext(userText);

  const response = await fetch(`${API_BASE}/api/assistant/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      messages: messages
        .filter((message) => message.id !== "welcome")
        .map(({ role, content }) => ({ role, content })),
      context: context || undefined,
    }),
  });

  if (!response.ok) {
    let detail = `Assistant request failed (${response.status})`;
    try {
      const data = (await response.json()) as { detail?: string };
      if (data.detail) {
        detail = data.detail;
      }
    } catch {
      // ignore parse errors
    }
    throw new Error(detail);
  }

  const data = (await response.json()) as { reply?: string };
  if (!data.reply?.trim()) {
    throw new Error("Empty assistant reply");
  }
  return correctHallucinations(userText, data.reply.trim());
}

/**
 * Groq-backed generative replies for general cyber questions.
 * In-app how-to uses the local guided map so product steps stay accurate.
 */
export const generativeProvider: AssistantReplyProvider = {
  async getReply(messages) {
    const userText = lastUserContent(messages);
    if (isOffensiveRequest(userText)) {
      return OUT_OF_SCOPE_REPLY;
    }

    // App navigation / product how-to → deterministic local guide only.
    if (isProductQuestion(userText)) {
      return localGuidedProvider.getReply(messages);
    }

    try {
      return await fetchGenerativeReply(messages);
    } catch (error) {
      console.warn("Generative assistant failed; using local fallback.", error);
      return localGuidedProvider.getReply(messages);
    }
  },
};
