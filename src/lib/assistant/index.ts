import { generativeProvider } from "./generativeProvider";
import type { AssistantReplyProvider } from "./types";

export type {
  AssistantMessage,
  AssistantReplyProvider,
  AssistantRole,
} from "./types";
export {
  OPEN_ASSISTANT_EVENT,
  openCyberAssistant,
  type OpenAssistantDetail,
} from "./events";

/**
 * Generative Cyber Assistant (Groq) with local knowledge-base fallback.
 */
export const assistantProvider: AssistantReplyProvider = generativeProvider;
