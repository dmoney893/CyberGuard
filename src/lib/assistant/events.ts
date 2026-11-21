export const OPEN_ASSISTANT_EVENT = "cyberguard:open-assistant";

export type OpenAssistantDetail = {
  question?: string;
};

/** Open the floating Cyber Assistant from anywhere in the app. */
export function openCyberAssistant(question?: string) {
  window.dispatchEvent(
    new CustomEvent<OpenAssistantDetail>(OPEN_ASSISTANT_EVENT, {
      detail: question ? { question } : {},
    }),
  );
}
