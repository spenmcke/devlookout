import crypto from "node:crypto";

export type MessageInput = {
  from: string;
  to: string;
  subject: string;
  body: string;
  locale?: string;
};

export type MessageRecord = MessageInput & {
  id: string;
  status: "queued" | "accepted" | "delivered";
  created_at: string;
};

const messages = new Map<string, MessageRecord>();

export function createMessage(input: MessageInput): MessageRecord {
  const record: MessageRecord = {
    id: `msg_${crypto.randomUUID().replaceAll("-", "").slice(0, 18)}`,
    from: input.from,
    to: input.to,
    subject: input.subject,
    body: input.body,
    locale: input.locale ?? "en_US",
    status: "queued",
    created_at: new Date().toISOString()
  };

  messages.set(record.id, record);
  return record;
}

export function getMessage(id: string): MessageRecord | undefined {
  return messages.get(id);
}

export function acceptWebhook(messageId: string): MessageRecord | undefined {
  const existing = messages.get(messageId);
  if (!existing) {
    return undefined;
  }

  const updated: MessageRecord = {
    ...existing,
    status: "delivered"
  };
  messages.set(messageId, updated);
  return updated;
}
