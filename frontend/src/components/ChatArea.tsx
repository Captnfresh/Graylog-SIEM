import { useState, useRef, useEffect, useCallback } from "react";
import { Shield } from "lucide-react";
import ChatMessage, { type Message } from "./ChatMessage";
import ChatInput from "./ChatInput";
import TypingIndicator from "./TypingIndicator";
import { streamChatMessage, subscribeToAlerts, type HistoryMessage } from "@/lib/api";

interface ChatAreaProps {
  pendingQuery: string | null;
  onQueryConsumed: () => void;
}

/** Build conversation history from the messages array for context passing to the API. */
function buildHistory(messages: Message[]): HistoryMessage[] {
  return messages
    .filter((m) => !m.isStreaming && m.content.trim())
    .map((m) => ({
      role: m.role,
      // For assistant messages, prefer the canonical summary from analysis
      content: m.role === "assistant" && m.analysis
        ? m.analysis.summary
        : m.content,
    }))
    .slice(-10) // keep last 10 turns (5 exchange pairs) to stay within token budget
}

const ChatArea = ({ pendingQuery, onQueryConsumed }: ChatAreaProps) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading]);

  const handleSend = useCallback(async (content: string) => {
    // Capture history from existing messages BEFORE adding the new user message
    const history = buildHistory(messages);

    const userMsg: Message = {
      id: crypto.randomUUID(),
      role: "user",
      content,
      timestamp: new Date(),
    };

    // Placeholder for the streaming assistant reply
    const assistantId = crypto.randomUUID();
    const placeholder: Message = {
      id: assistantId,
      role: "assistant",
      content: "",
      timestamp: new Date(),
      isStreaming: true,
    };

    setMessages((prev) => [...prev, userMsg, placeholder]);
    setIsLoading(true);

    try {
      for await (const event of streamChatMessage(content, history)) {
        if (event.type === "text" && event.delta !== undefined) {
          setMessages((prev) =>
            prev.map((m) =>
              m.id === assistantId
                ? { ...m, content: m.content + event.delta }
                : m
            )
          );
        } else if (event.type === "done" && event.analysis) {
          setMessages((prev) =>
            prev.map((m) =>
              m.id === assistantId
                ? {
                    ...m,
                    // Replace streamed text with the canonical summary so they match exactly
                    content: event.analysis!.summary,
                    analysis: event.analysis,
                    isStreaming: false,
                  }
                : m
            )
          );
        }
      }
    } catch (err) {
      setMessages((prev) =>
        prev.map((m) =>
          m.id === assistantId
            ? {
                ...m,
                content: `Unable to reach the OmniLog backend. (${
                  err instanceof Error ? err.message : "Unknown error"
                })`,
                isStreaming: false,
              }
            : m
        )
      );
    } finally {
      setIsLoading(false);
    }
  }, [messages]);

  // Subscribe to live alert stream — inject alert messages into chat unprompted
  useEffect(() => {
    const es = subscribeToAlerts((event) => {
      const alertMsg: Message = {
        id: crypto.randomUUID(),
        role: "assistant",
        content: `Risk score spiked to ${event.riskScore}% — suspicious activity detected in the last 5 minutes. Here's what triggered it:`,
        timestamp: new Date(),
        analysis: event.analysis,
        isAlert: true,
      };
      setMessages((prev) => [...prev, alertMsg]);
    });
    return () => es.close();
  }, []);

  // Handle external queries (sidebar quick actions, follow-up chips)
  useEffect(() => {
    if (pendingQuery) {
      handleSend(pendingQuery);
      onQueryConsumed();
    }
  }, [pendingQuery, onQueryConsumed, handleSend]);

  const handleReact = useCallback((messageId: string, reaction: "up" | "down") => {
    setMessages((prev) =>
      prev.map((m) =>
        m.id === messageId
          ? { ...m, reaction: m.reaction === reaction ? undefined : reaction }
          : m
      )
    );
  }, []);

  const isCurrentlyStreaming = messages.some((m) => m.isStreaming);

  return (
    <div className="flex-1 flex flex-col min-h-0">
      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto bg-grid">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-4 space-y-4">
            <div className="h-16 w-16 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center glow-primary">
              <Shield className="h-8 w-8 text-primary" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-foreground mb-1">Welcome to OmniLog</h2>
              <p className="text-sm text-muted-foreground max-w-md">
                Your AI-powered SIEM assistant. Ask me about security events, failed logins,
                network anomalies, or any threats detected in your environment.
              </p>
            </div>
            <div className="font-mono text-xs text-muted-foreground/50">
              Graylog Integration • Claude AI Analysis • Real-time Threat Intelligence
            </div>
          </div>
        ) : (
          <div className="py-4">
            {messages.map((msg) => (
              <ChatMessage
                key={msg.id}
                message={msg}
                onFollowUp={handleSend}
                onReact={handleReact}
              />
            ))}
            {/* Only show typing indicator if NOT already streaming a response */}
            {isLoading && !isCurrentlyStreaming && <TypingIndicator />}
          </div>
        )}
      </div>

      {/* Input */}
      <ChatInput onSend={handleSend} isLoading={isLoading} />
    </div>
  );
};

export default ChatArea;
