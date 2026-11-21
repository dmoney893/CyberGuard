export type AssistantRole = "user" | "assistant";

export type AssistantMessage = {
  id: string;
  role: AssistantRole;
  content: string;
};

/**
 * Local guided reply backend (knowledge base + CyberGuard page redirects).
 */
export type AssistantReplyProvider = {
  getReply: (messages: AssistantMessage[]) => Promise<string>;
};
