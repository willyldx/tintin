export interface SessionMessage {
  text: string;
  final?: boolean;
  priority?: "user" | "background";
}

export type SendToSessionFn = (sessionId: string, message: SessionMessage) => Promise<void>;
