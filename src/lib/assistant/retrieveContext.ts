import { KNOWLEDGE_TOPICS } from "./knowledgeBase";
import { PLATFORM_FEATURES } from "./platformGuide";

function normalize(text: string): string {
  return text
    .toLowerCase()
    .replace(/[’‘]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[^a-z0-9@./+\-'\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function includesKeyword(text: string, keyword: string): boolean {
  const needle = keyword.toLowerCase().trim();
  if (!needle) {
    return false;
  }
  if (needle.includes(" ")) {
    return text.includes(needle);
  }
  const pattern = new RegExp(
    `(^|[^a-z0-9])${needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^a-z0-9]|$)`,
  );
  return pattern.test(text);
}

const PRODUCT_TERMS = [
  "cyberguard",
  "this app",
  "the app",
  "in the app",
  "on the platform",
  "sidebar",
  "team security",
  "organization",
  "create a team",
  "create team",
  "create an organization",
  "create organization",
  "invite member",
  "invite teammate",
  "join organization",
  "join team",
  "email scanner",
  "website tracker",
  "security checker",
  "device scanner",
  "system guardian",
  "cyber assistant",
  "settings",
  "dashboard",
  "reports",
  "news",
];

const NAV_INTENTS = [
  "where is",
  "where can i",
  "where do i",
  "how do i open",
  "how do i find",
  "how do i use",
  "how do i create",
  "how do i join",
  "how do i invite",
  "how to open",
  "how to find",
  "how to use",
  "how to create",
  "how to join",
  "take me to",
  "go to",
  "open the",
  "find the",
  "show me",
];

/** True when the user is asking about CyberGuard itself, not general cyber advice. */
export function isProductQuestion(userText: string): boolean {
  const text = normalize(userText);
  if (!text) {
    return false;
  }

  if (PRODUCT_TERMS.some((term) => text.includes(term))) {
    return true;
  }

  if (NAV_INTENTS.some((intent) => text.includes(intent))) {
    return true;
  }

  return PLATFORM_FEATURES.some(
    (feature) =>
      text.includes(feature.name.toLowerCase()) ||
      text.includes(feature.path.replace(/^\//, "").replace(/-/g, " ")),
  );
}

function compactFeatureCatalog(): string {
  return PLATFORM_FEATURES.filter((feature) => feature.id !== "auth")
    .map(
      (feature) =>
        `${feature.name} (${feature.path}): ${feature.summary} How: ${feature.howTo}`,
    )
    .join("\n\n");
}

/**
 * Pull the most relevant local knowledge + CyberGuard page notes
 * so the generative model stays grounded.
 */
export function buildAssistantContext(userText: string): string {
  const text = normalize(userText);
  if (!text) {
    return "";
  }

  const productQuestion = isProductQuestion(text);
  const parts: string[] = [];

  if (productQuestion) {
    parts.push(
      "Official CyberGuard product map (only trust these pages and steps):\n\n" +
        compactFeatureCatalog(),
    );
  }

  const topics = KNOWLEDGE_TOPICS.map((topic) => {
    let score = 0;
    for (const keyword of topic.keywords) {
      if (includesKeyword(text, keyword)) {
        score += keyword.split(/\s+/).length >= 2 ? 3 : 1;
      }
    }
    return { topic, score };
  })
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, productQuestion ? 1 : 3);

  const features = PLATFORM_FEATURES.map((feature) => {
    let score = 0;
    for (const keyword of feature.keywords) {
      if (includesKeyword(text, keyword) || text.includes(keyword)) {
        score += keyword.split(/\s+/).length >= 2 ? 4 : 1;
      }
    }
    if (text.includes(feature.name.toLowerCase())) {
      score += 5;
    }
    // Never let Settings win over Team Security for team/org creation.
    if (
      feature.id === "settings" &&
      (text.includes("team") || text.includes("organization"))
    ) {
      score = 0;
    }
    if (
      feature.id === "team-security" &&
      (text.includes("team") || text.includes("organization"))
    ) {
      score += 8;
    }
    return { feature, score };
  })
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 3);

  if (!productQuestion && topics.length > 0) {
    parts.push(
      topics
        .map(
          (entry) =>
            `Topic: ${entry.topic.title}\n${entry.topic.reply.slice(0, 1200)}`,
        )
        .join("\n\n---\n\n"),
    );
  }

  if (features.length > 0) {
    parts.push(
      "Matched CyberGuard pages for this question:\n\n" +
        features
          .map(
            (entry) =>
              `Feature: ${entry.feature.name} (${entry.feature.path})\n${entry.feature.summary}\n${entry.feature.howTo}`,
          )
          .join("\n\n"),
    );
  }

  return parts.join("\n\n====\n\n").slice(0, 5500);
}
