import { useState, useRef, useEffect, useCallback } from "react";
import { Shield } from "lucide-react";
import ChatMessage, { type Message } from "./ChatMessage";
import ChatInput from "./ChatInput";
import TypingIndicator from "./TypingIndicator";
import { sendChatMessage } from "@/lib/api";

interface ChatAreaProps {
  pendingQuery: string | null;
  onQueryConsumed: () => void;
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
    const userMsg: Message = {
      id: crypto.randomUUID(),
      role: "user",
      content,
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setIsLoading(true);

    try {
      const data = await sendChatMessage(content);
      const aiMsg: Message = {
        id: crypto.randomUUID(),
        role: "assistant",
        content: data.content,
        timestamp: new Date(),
        analysis: data.analysis,
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch (err) {
      const errMsg: Message = {
        id: crypto.randomUUID(),
        role: "assistant",
        content: `Unable to reach the OmniLog backend. Make sure the API server is running. (${err instanceof Error ? err.message : "Unknown error"})`,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, errMsg]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Handle external queries from sidebar
  useEffect(() => {
    if (pendingQuery) {
      handleSend(pendingQuery);
      onQueryConsumed();
    }
  }, [pendingQuery, onQueryConsumed, handleSend]);

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
                Your AI-powered SIEM assistant. Ask me about security events, failed logins, network anomalies, or any threats detected in your environment.
              </p>
            </div>
            <div className="font-mono text-xs text-muted-foreground/50">
              Graylog Integration • Claude AI Analysis • Real-time Threat Intelligence
            </div>
          </div>
        ) : (
          <div className="py-4">
            {messages.map((msg) => (
              <ChatMessage key={msg.id} message={msg} />
            ))}
            {isLoading && <TypingIndicator />}
          </div>
        )}
      </div>

      {/* Input */}
      <ChatInput
        onSend={handleSend}
        isLoading={isLoading}
      />
    </div>
  );
};

export default ChatArea;
