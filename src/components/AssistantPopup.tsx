import { useEffect, useRef, useState } from "react";
import type { FormEvent, KeyboardEvent, ReactNode } from "react";
import { Link } from "react-router-dom";
import { Bot, SendHorizontal, X } from "lucide-react";

import {
  OPEN_ASSISTANT_EVENT,
  assistantProvider,
  type AssistantMessage,
  type OpenAssistantDetail,
} from "../lib/assistant";
import { useProfile } from "../context/ProfileContext";

import "./AssistantPopup.css";

function createId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function welcomeMessage(firstName?: string | null): AssistantMessage {
  const name = firstName?.trim();
  return {
    id: "welcome",
    role: "assistant",
    content: name
      ? `Hi ${name}, how can I help you?`
      : "Hi, how can I help you?",
  };
}

const LINK_PATTERN = /\[([^\]]+)\]\((\/[a-z0-9\-/?=#]*)\)/gi;

function renderInline(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  const pattern = new RegExp(LINK_PATTERN.source, "gi");

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) {
      nodes.push(text.slice(lastIndex, match.index));
    }
    nodes.push(
      <Link
        key={`${match.index}-${match[2]}`}
        className="assistant-inline-link"
        to={match[2]}
      >
        {match[1]}
      </Link>,
    );
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < text.length) {
    nodes.push(text.slice(lastIndex));
  }

  return nodes.length > 0 ? nodes : [text];
}

function plainText(content: string): string {
  return content
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/__(.+?)__/g, "$1")
    .replace(/(?<!\w)\*(?!\s)(.+?)(?<!\s)\*(?!\w)/g, "$1")
    .replace(/\*\*/g, "")
    .replace(/^#{1,6}\s*/gm, "")
    .replace(/^[\-*•]\s+/gm, "")
    .trim();
}

function formatReply(content: string) {
  return plainText(content)
    .split("\n")
    .map((line, index) => {
      const trimmed = line.trim();
      if (!trimmed) {
        return <br key={index} />;
      }

      if (/^\d+\.\s/.test(trimmed)) {
        return (
          <p key={index} className="assistant-msg-step">
            {renderInline(trimmed)}
          </p>
        );
      }

      return <p key={index}>{renderInline(trimmed)}</p>;
    });
}

type AssistantPopupProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
};

function AssistantPopup({ open, onOpenChange }: AssistantPopupProps) {
  const { profile } = useProfile();
  const firstName = profile?.first_name?.trim() || null;
  const [messages, setMessages] = useState<AssistantMessage[]>(() => [
    welcomeMessage(null),
  ]);
  const [input, setInput] = useState("");
  const [isReplying, setIsReplying] = useState(false);
  const threadRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const messagesRef = useRef(messages);
  const isReplyingRef = useRef(isReplying);
  const pendingQuestion = useRef<string | null>(null);

  useEffect(() => {
    setMessages((prev) => {
      if (prev[0]?.id !== "welcome") {
        return prev;
      }
      const nextWelcome = welcomeMessage(firstName);
      if (prev[0].content === nextWelcome.content) {
        return prev;
      }
      return [nextWelcome, ...prev.slice(1)];
    });
  }, [firstName]);

  useEffect(() => {
    messagesRef.current = messages;
    isReplyingRef.current = isReplying;
  }, [messages, isReplying]);

  useEffect(() => {
    const el = threadRef.current;
    if (el && open) {
      el.scrollTop = el.scrollHeight;
    }
  }, [messages, isReplying, open]);

  useEffect(() => {
    if (open) {
      const timer = window.setTimeout(() => inputRef.current?.focus(), 80);
      return () => window.clearTimeout(timer);
    }
  }, [open]);

  async function sendMessage(rawText: string) {
    const text = rawText.trim();
    if (!text || isReplyingRef.current) {
      return;
    }

    const userMessage: AssistantMessage = {
      id: createId(),
      role: "user",
      content: text,
    };

    const nextMessages = [...messagesRef.current, userMessage];
    setMessages(nextMessages);
    setInput("");
    setIsReplying(true);
    isReplyingRef.current = true;

    try {
      const reply = await assistantProvider.getReply(nextMessages);
      setMessages((prev) => [
        ...prev,
        {
          id: createId(),
          role: "assistant",
          content: reply,
        },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          id: createId(),
          role: "assistant",
          content:
            "Something went wrong while getting a reply. Please try again.",
        },
      ]);
    } finally {
      setIsReplying(false);
      isReplyingRef.current = false;
    }
  }

  useEffect(() => {
    function onOpenEvent(event: Event) {
      const detail = (event as CustomEvent<OpenAssistantDetail>).detail;
      onOpenChange(true);
      const question = detail?.question?.trim();
      if (question) {
        pendingQuestion.current = question;
      }
    }

    window.addEventListener(OPEN_ASSISTANT_EVENT, onOpenEvent);
    return () => window.removeEventListener(OPEN_ASSISTANT_EVENT, onOpenEvent);
  }, [onOpenChange]);

  useEffect(() => {
    if (!open || !pendingQuestion.current) {
      return;
    }
    const question = pendingQuestion.current;
    pendingQuestion.current = null;
    void sendMessage(question);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useEffect(() => {
    if (!open) {
      return;
    }

    function onKeyDown(event: globalThis.KeyboardEvent) {
      if (event.key === "Escape") {
        onOpenChange(false);
      }
    }

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onOpenChange]);

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    void sendMessage(input);
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void sendMessage(input);
    }
  }

  return (
    <div className="assistant-popup-root">
      {open && (
        <div
          className="assistant-popup-panel"
          role="dialog"
          aria-modal="true"
          aria-label="Cyber Assistant"
        >
          <header className="assistant-popup-header">
            <div className="assistant-popup-title">
              <div className="assistant-popup-icon">
                <Bot size={18} />
              </div>
              <div>
                <h2>Cyber Assistant</h2>
                <p>Security help, right here</p>
              </div>
            </div>
            <button
              type="button"
              className="assistant-popup-close"
              onClick={() => onOpenChange(false)}
              aria-label="Close assistant"
            >
              <X size={18} />
            </button>
          </header>

          <div className="assistant-popup-thread" ref={threadRef}>
            {messages.map((message) => (
              <div
                key={message.id}
                className={`assistant-bubble assistant-bubble-${message.role}`}
              >
                {message.role === "assistant" ? (
                  <div className="assistant-bubble-body">
                    {formatReply(message.content)}
                  </div>
                ) : (
                  <p>{message.content}</p>
                )}
              </div>
            ))}

            {isReplying && (
              <div className="assistant-bubble assistant-bubble-assistant">
                <div
                  className="assistant-typing"
                  aria-label="Assistant is typing"
                >
                  <span />
                  <span />
                  <span />
                </div>
              </div>
            )}
          </div>

          <form className="assistant-popup-composer" onSubmit={onSubmit}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={onKeyDown}
              placeholder="Ask a security question…"
              rows={2}
              disabled={isReplying}
              aria-label="Message to Cyber Assistant"
            />
            <button
              type="submit"
              className="assistant-send"
              disabled={isReplying || !input.trim()}
              aria-label="Send message"
            >
              <SendHorizontal size={18} />
            </button>
          </form>
        </div>
      )}

      <button
        type="button"
        className={`assistant-fab${open ? " is-open" : ""}`}
        onClick={() => onOpenChange(!open)}
        aria-label={open ? "Close Cyber Assistant" : "Open Cyber Assistant"}
        aria-expanded={open}
      >
        {open ? <X size={22} /> : <Bot size={22} />}
      </button>
    </div>
  );
}

export default AssistantPopup;
