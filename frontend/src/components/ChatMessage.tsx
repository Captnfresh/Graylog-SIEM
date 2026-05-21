import { motion } from "framer-motion";
import { User, Shield, Zap, Bell, ThumbsUp, ThumbsDown } from "lucide-react";
import ThreatCard from "./ThreatCard";
import type { ThreatAnalysis } from "@/lib/api";

export interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
  analysis?: ThreatAnalysis;
  isStreaming?: boolean;
  isAlert?: boolean;
  reaction?: "up" | "down";
}

interface ChatMessageProps {
  message: Message;
  onFollowUp?: (question: string) => void;
  onReact?: (messageId: string, reaction: "up" | "down") => void;
}

const ChatMessage = ({ message, onFollowUp, onReact }: ChatMessageProps) => {
  const isUser    = message.role === "user";
  const followUps = message.analysis?.followUps ?? [];
  const canReact  = !isUser && !message.isStreaming;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={`group flex gap-3 px-4 py-3 ${isUser ? "justify-end" : ""}`}
    >
      {!isUser && (
        <div className={`h-8 w-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${
          message.isAlert
            ? "bg-destructive/15 border border-destructive/30"
            : "bg-primary/10 border border-primary/20"
        }`}>
          {message.isAlert
            ? <Bell className="h-4 w-4 text-destructive animate-pulse" />
            : <Shield className="h-4 w-4 text-primary" />
          }
        </div>
      )}

      <div className={`max-w-[80%] space-y-2 ${isUser ? "items-end" : ""}`}>

        {/* LIVE ALERT badge */}
        {message.isAlert && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="inline-flex items-center gap-1.5 text-[10px] font-mono font-bold uppercase tracking-widest px-2 py-1 rounded border border-destructive/40 bg-destructive/10 text-destructive"
          >
            <span className="h-1.5 w-1.5 rounded-full bg-destructive animate-pulse" />
            Live Alert
          </motion.div>
        )}

        {/* Message bubble */}
        <div
          className={`rounded-2xl px-4 py-2.5 text-sm leading-relaxed ${
            isUser
              ? "bg-primary text-primary-foreground rounded-br-md"
              : message.isAlert
                ? "bg-card border border-destructive/30 rounded-bl-md"
                : "bg-card border border-border rounded-bl-md"
          }`}
        >
          {message.content}
          {message.isStreaming && (
            <span className="inline-block w-[2px] h-4 bg-primary/70 animate-pulse ml-0.5 translate-y-[2px]" />
          )}
        </div>

        {/* Threat analysis card */}
        {message.analysis && !message.isStreaming && (
          <ThreatCard
            analysis={message.analysis}
            onIpClick={(query) => onFollowUp?.(`What activity is associated with ${query}?`)}
          />
        )}

        {/* Follow-up chips */}
        {!message.isStreaming && followUps.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="flex flex-wrap gap-2 pt-1"
          >
            {followUps.map((q, i) => (
              <button
                key={i}
                onClick={() => onFollowUp?.(q)}
                className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-full border border-primary/25 text-primary/75 bg-primary/5 hover:bg-primary/15 hover:text-primary hover:border-primary/50 transition-all"
              >
                <Zap className="h-3 w-3 shrink-0" />
                {q}
              </button>
            ))}
          </motion.div>
        )}

        {/* Timestamp + reaction row */}
        <div className="flex items-center gap-2 px-1">
          <span className="text-[10px] font-mono text-muted-foreground">
            {message.timestamp.toLocaleTimeString()}
          </span>

          {/* Reaction buttons — visible on hover or when a reaction is set */}
          {canReact && (
            <div className={`flex gap-0.5 transition-opacity duration-200 ${
              message.reaction ? "opacity-100" : "opacity-0 group-hover:opacity-100"
            }`}>
              <button
                onClick={() => onReact?.(message.id, "up")}
                title="Helpful"
                className={`p-1 rounded transition-colors ${
                  message.reaction === "up"
                    ? "text-green-400 bg-green-400/10"
                    : "text-muted-foreground/40 hover:text-green-400 hover:bg-green-400/10"
                }`}
              >
                <ThumbsUp className="h-3 w-3" />
              </button>
              <button
                onClick={() => onReact?.(message.id, "down")}
                title="Not helpful"
                className={`p-1 rounded transition-colors ${
                  message.reaction === "down"
                    ? "text-red-400 bg-red-400/10"
                    : "text-muted-foreground/40 hover:text-red-400 hover:bg-red-400/10"
                }`}
              >
                <ThumbsDown className="h-3 w-3" />
              </button>
            </div>
          )}
        </div>
      </div>

      {isUser && (
        <div className="h-8 w-8 rounded-lg bg-secondary border border-border flex items-center justify-center shrink-0 mt-0.5">
          <User className="h-4 w-4 text-muted-foreground" />
        </div>
      )}
    </motion.div>
  );
};

export default ChatMessage;
