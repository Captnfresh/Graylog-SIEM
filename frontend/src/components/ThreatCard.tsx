import { motion } from "framer-motion";
import { AlertTriangle, Shield, ShieldAlert, ShieldCheck, Server, ArrowRight } from "lucide-react";
import type { ThreatAnalysis, LogEntry } from "@/lib/api";

interface ThreatCardProps {
  analysis: ThreatAnalysis;
  onIpClick?: (ip: string) => void;
}

const levelConfig = {
  Low:      { icon: ShieldCheck,  colorClass: "text-accent",        bgClass: "bg-accent/10",      borderClass: "border-accent/30" },
  Medium:   { icon: Shield,       colorClass: "text-warning",       bgClass: "bg-warning/10",     borderClass: "border-warning/30" },
  High:     { icon: AlertTriangle,colorClass: "text-neon-orange",   bgClass: "bg-warning/10",     borderClass: "border-warning/30" },
  Critical: { icon: ShieldAlert,  colorClass: "text-destructive",   bgClass: "bg-destructive/10", borderClass: "border-destructive/30" },
};

const logLevelStyle: Record<LogEntry["level"], { badge: string; row: string }> = {
  CRITICAL: { badge: "bg-destructive/20 text-destructive border-destructive/40",   row: "border-l-2 border-destructive/50" },
  ERROR:    { badge: "bg-orange-500/20 text-orange-400 border-orange-500/40",       row: "border-l-2 border-orange-500/50" },
  WARNING:  { badge: "bg-warning/20 text-warning border-warning/40",               row: "border-l-2 border-warning/50" },
  INFO:     { badge: "bg-muted text-muted-foreground border-border",               row: "border-l-2 border-border/30" },
};

const IP_RE = /(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/g;

/** Splits a log message and wraps IP addresses in clickable chips. */
const LogMessage = ({
  message,
  onIpClick,
}: {
  message: string;
  onIpClick?: (ip: string) => void;
}) => {
  const parts = message.split(IP_RE);
  return (
    <span>
      {parts.map((part, i) =>
        IP_RE.test(part) ? (
          <button
            key={i}
            onClick={() => onIpClick?.(part)}
            title={`Query activity from ${part}`}
            className="inline-flex items-center px-1.5 py-0 mx-0.5 rounded text-[11px] font-mono bg-primary/15 text-primary border border-primary/25 hover:bg-primary/30 hover:border-primary/50 transition-colors leading-5"
          >
            {part}
          </button>
        ) : (
          <span key={i}>{part}</span>
        )
      )}
    </span>
  );
};

const ThreatCard = ({ analysis, onIpClick }: ThreatCardProps) => {
  const config  = levelConfig[analysis.threatLevel];
  const Icon    = config.icon;
  const logs    = analysis.logEntries;

  // Severity counts for the log summary bar
  const counts = logs.reduce(
    (acc, l) => { acc[l.level] = (acc[l.level] ?? 0) + 1; return acc; },
    {} as Record<string, number>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`rounded-lg border ${config.borderClass} ${config.bgClass} p-4 space-y-3`}
    >
      {/* Threat Level Badge */}
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 ${config.colorClass}`} />
        <span className={`text-xs font-mono font-bold uppercase tracking-wider ${config.colorClass}`}>
          {analysis.threatLevel} Threat
        </span>
      </div>

      {/* Summary */}
      <p className="text-sm text-foreground/90 leading-relaxed">{analysis.summary}</p>

      {/* Affected Systems */}
      {analysis.affectedSystems.length > 0 && (
        <div className="space-y-1.5">
          <span className="text-xs font-mono text-muted-foreground">AFFECTED SYSTEMS</span>
          <div className="flex flex-wrap gap-1.5">
            {analysis.affectedSystems.map((sys) => (
              <span
                key={sys}
                className="inline-flex items-center gap-1 text-xs font-mono px-2 py-1 rounded bg-muted border border-border"
              >
                <Server className="h-3 w-3 text-muted-foreground" />
                {sys}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Recommended Actions */}
      <div className="space-y-1.5">
        <span className="text-xs font-mono text-muted-foreground">RECOMMENDED ACTIONS</span>
        <ul className="space-y-1">
          {analysis.recommendedActions.map((action, i) => (
            <li key={i} className="flex items-start gap-2 text-sm text-foreground/80">
              <ArrowRight className="h-3 w-3 mt-1 text-primary shrink-0" />
              {action}
            </li>
          ))}
        </ul>
      </div>

      {/* Rich Log Entries */}
      {logs.length > 0 && (
        <div className="space-y-1.5">
          {/* Header with severity count badges */}
          <div className="flex items-center justify-between flex-wrap gap-1">
            <span className="text-xs font-mono text-muted-foreground">
              LOG ENTRIES ({logs.length})
            </span>
            <div className="flex gap-1.5">
              {(["CRITICAL", "ERROR", "WARNING", "INFO"] as const).map((lvl) =>
                counts[lvl] ? (
                  <span
                    key={lvl}
                    className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded border ${logLevelStyle[lvl].badge}`}
                  >
                    {counts[lvl]} {lvl.slice(0, 4)}
                  </span>
                ) : null
              )}
            </div>
          </div>

          {/* Log rows */}
          <div className="space-y-1 max-h-52 overflow-y-auto rounded-md">
            {logs.map((log, i) => {
              const style = logLevelStyle[log.level];
              return (
                <div
                  key={i}
                  className={`${style.row} text-xs font-mono p-2 rounded-r bg-background/50 border border-border/50`}
                >
                  <div className="flex items-center gap-2 flex-wrap">
                    {/* Timestamp */}
                    <span className="text-muted-foreground shrink-0">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </span>
                    {/* Level badge */}
                    <span className={`px-1 py-0.5 rounded border text-[10px] font-bold shrink-0 ${style.badge}`}>
                      {log.level}
                    </span>
                    {/* Source */}
                    <button
                      onClick={() => onIpClick?.(`source:${log.source}`)}
                      title={`Query logs from ${log.source}`}
                      className="text-primary/70 hover:text-primary transition-colors shrink-0"
                    >
                      {log.source}
                    </button>
                  </div>
                  {/* Message with highlighted IPs */}
                  <div className="mt-1 text-foreground/70 leading-relaxed break-words">
                    <LogMessage message={log.message} onIpClick={onIpClick} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </motion.div>
  );
};

export default ThreatCard;
