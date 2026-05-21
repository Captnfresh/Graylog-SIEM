import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Shield } from "lucide-react";

const STAGES = [
  "Querying Graylog...",
  "Analysing logs...",
  "Generating insights...",
];

const STAGE_DELAYS_MS = [1200, 3000]; // when to advance to stage 1, then stage 2

const TypingIndicator = () => {
  const [stage, setStage] = useState(0);

  useEffect(() => {
    const timers = STAGE_DELAYS_MS.map((delay, i) =>
      setTimeout(() => setStage(i + 1), delay)
    );
    return () => timers.forEach(clearTimeout);
  }, []);

  return (
    <div className="flex items-center gap-3 px-4 py-3">
      {/* Shield avatar matching assistant messages */}
      <div className="h-8 w-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
        <Shield className="h-4 w-4 text-primary" />
      </div>

      <div className="flex items-center gap-2 bg-card border border-border rounded-2xl rounded-bl-md px-4 py-3">
        {/* Cycling status label */}
        <AnimatePresence mode="wait">
          <motion.span
            key={stage}
            initial={{ opacity: 0, y: 3 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -3 }}
            transition={{ duration: 0.25 }}
            className="text-xs text-primary font-mono mr-1 min-w-[140px]"
          >
            {STAGES[stage]}
          </motion.span>
        </AnimatePresence>

        {/* Pulsing dots */}
        {[0, 1, 2].map((i) => (
          <motion.div
            key={i}
            className="h-1.5 w-1.5 rounded-full bg-primary"
            animate={{ opacity: [0.3, 1, 0.3], scale: [1, 1.25, 1] }}
            transition={{ duration: 1, repeat: Infinity, delay: i * 0.2 }}
          />
        ))}
      </div>
    </div>
  );
};

export default TypingIndicator;
