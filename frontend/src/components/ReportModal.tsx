import { useState, useEffect } from "react";
import { createPortal } from "react-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  X, Printer, Shield, AlertTriangle, ShieldCheck, ShieldAlert,
  CheckCircle2, Clock, ArrowRight, BarChart3, TrendingUp, PieChart,
  Lightbulb, Star
} from "lucide-react";
import { generateReport, type SecurityReport, type ReportRisk } from "@/lib/api";

interface ReportModalProps {
  onClose: () => void;
}

// ── Risk badge ────────────────────────────────────────────────────────────────
const riskConfig: Record<ReportRisk["level"], { color: string; bg: string; border: string; icon: typeof Shield }> = {
  Low:    { color: "text-green-400",  bg: "bg-green-400/10",  border: "border-green-400/30",  icon: ShieldCheck  },
  Medium: { color: "text-yellow-400", bg: "bg-yellow-400/10", border: "border-yellow-400/30", icon: Shield       },
  High:   { color: "text-red-400",    bg: "bg-red-400/10",    border: "border-red-400/30",    icon: ShieldAlert  },
};

const statusConfig = {
  Healthy:          { color: "text-green-400",  bg: "bg-green-400/10",  border: "border-green-400/30",  icon: ShieldCheck  },
  "Needs Attention":{ color: "text-yellow-400", bg: "bg-yellow-400/10", border: "border-yellow-400/30", icon: Shield       },
  Critical:         { color: "text-red-400",    bg: "bg-red-400/10",    border: "border-red-400/30",    icon: ShieldAlert  },
};

const vizIcon = { bar: BarChart3, line: TrendingUp, pie: PieChart };
const priorityColor = { Immediate: "text-red-400", "Short-term": "text-yellow-400", "Long-term": "text-green-400" };

// ── Section wrapper ───────────────────────────────────────────────────────────
const Section = ({ num, title, children }: { num: string; title: string; children: React.ReactNode }) => (
  <div className="space-y-3 print:break-inside-avoid">
    <div className="flex items-center gap-3 border-b border-border/50 pb-2">
      <span className="text-[10px] font-mono font-bold text-primary/60 bg-primary/10 border border-primary/20 rounded px-1.5 py-0.5">
        {num}
      </span>
      <h3 className="text-sm font-mono font-bold uppercase tracking-widest text-foreground/80">{title}</h3>
    </div>
    {children}
  </div>
);

// ── Main component ─────────────────────────────────────────────────────────────
const ReportModal = ({ onClose }: ReportModalProps) => {
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);

  // Auto-generate on mount
  useEffect(() => {
    generateReport()
      .then(setReport)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const handlePrint = () => window.print();

  const StatusIcon = report ? statusConfig[report.overallStatus].icon : Shield;

  return createPortal(
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 bg-background/95 backdrop-blur-sm flex flex-col print:static print:bg-white print:text-black"
      >
        {/* ── Toolbar (hidden when printing) ── */}
        <div className="print:hidden flex items-center justify-between px-6 py-3 border-b border-border bg-card/80 shrink-0">
          <div className="flex items-center gap-3">
            <Shield className="h-5 w-5 text-primary" />
            <span className="font-mono font-bold text-foreground">Security Report</span>
            {report && (
              <span className="text-xs font-mono text-muted-foreground">
                Generated {report.generatedAt}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              disabled={!report}
              className="inline-flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
            >
              <Printer className="h-3.5 w-3.5" />
              Print / Save PDF
            </button>
            <button
              onClick={onClose}
              className="p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* ── Body ── */}
        <div className="flex-1 overflow-y-auto print:overflow-visible">
          {loading && (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-muted-foreground">
              <motion.div animate={{ rotate: 360 }} transition={{ duration: 2, repeat: Infinity, ease: "linear" }}>
                <Shield className="h-10 w-10 text-primary" />
              </motion.div>
              <p className="text-sm font-mono">Analysing logs and generating report…</p>
            </div>
          )}

          {error && (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-destructive">
              <AlertTriangle className="h-10 w-10" />
              <p className="text-sm font-mono">{error}</p>
            </div>
          )}

          {report && (
            <div className="max-w-4xl mx-auto px-6 py-8 space-y-8 print:px-0 print:py-4 print:space-y-6">

              {/* ── Cover ── */}
              <div className="text-center space-y-2 pb-6 border-b border-border print:pb-4">
                <div className="inline-flex items-center justify-center h-14 w-14 rounded-2xl bg-primary/10 border border-primary/20 mb-3">
                  <Shield className="h-7 w-7 text-primary" />
                </div>
                <h1 className="text-2xl font-bold font-mono text-foreground print:text-black">
                  System Log Analysis Report
                </h1>
                <p className="text-sm text-muted-foreground font-mono print:text-gray-600">
                  Generated {report.generatedAt} &nbsp;·&nbsp; Log range: {report.logTimeRange.earliest} → {report.logTimeRange.latest}
                </p>
              </div>

              {/* ── 9. Boardroom Summary (top, most important for skimmers) ── */}
              <div className={`rounded-xl border p-5 ${statusConfig[report.overallStatus].bg} ${statusConfig[report.overallStatus].border}`}>
                <div className="flex items-center gap-2 mb-3">
                  <StatusIcon className={`h-5 w-5 ${statusConfig[report.overallStatus].color}`} />
                  <span className={`font-mono font-bold text-sm uppercase tracking-wider ${statusConfig[report.overallStatus].color}`}>
                    {report.overallStatus}
                  </span>
                </div>
                <p className="text-sm leading-relaxed text-foreground/90 print:text-black">{report.boardroomSummary}</p>
              </div>

              {/* ── 10. Top 3 Takeaways ── */}
              <Section num="01" title="Top 3 Takeaways">
                <div className="grid gap-2">
                  {report.topTakeaways.map((t, i) => (
                    <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-muted/50 border border-border">
                      <Star className="h-4 w-4 text-primary shrink-0 mt-0.5" />
                      <span className="text-sm text-foreground/90 print:text-black">{t}</span>
                    </div>
                  ))}
                </div>
              </Section>

              {/* ── 2. Executive Summary ── */}
              <Section num="02" title="Executive Summary">
                <p className="text-sm leading-relaxed text-foreground/80 print:text-black">{report.executiveSummary}</p>
              </Section>

              {/* ── 3. Key Insights ── */}
              <Section num="03" title="Key Insights">
                <ul className="space-y-2">
                  {report.keyInsights.map((insight, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-foreground/80 print:text-black">
                      <Lightbulb className="h-4 w-4 text-yellow-400 shrink-0 mt-0.5" />
                      {insight}
                    </li>
                  ))}
                </ul>
              </Section>

              {/* ── 4. Risk Assessment ── */}
              <Section num="04" title="Risk Assessment">
                <div className="space-y-3">
                  {report.risks.map((risk, i) => {
                    const cfg  = riskConfig[risk.level];
                    const Icon = cfg.icon;
                    return (
                      <div key={i} className={`rounded-lg border ${cfg.border} ${cfg.bg} p-4 space-y-2 print:break-inside-avoid`}>
                        <div className="flex items-center gap-2">
                          <Icon className={`h-4 w-4 ${cfg.color}`} />
                          <span className={`text-xs font-mono font-bold uppercase tracking-wider ${cfg.color}`}>
                            {risk.level} Risk
                          </span>
                          <span className="text-sm font-semibold text-foreground/90 print:text-black ml-1">— {risk.title}</span>
                        </div>
                        <p className="text-sm text-foreground/75 print:text-black">{risk.description}</p>
                        <div className="flex flex-wrap gap-4 text-xs text-muted-foreground print:text-gray-500">
                          <span><Clock className="h-3 w-3 inline mr-1" />{risk.affectedTime}</span>
                          <span className="text-foreground/70 print:text-black"><strong>Business impact:</strong> {risk.businessImpact}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </Section>

              {/* ── 5. Notable Events ── */}
              {report.notableEvents.length > 0 && (
                <Section num="05" title="Notable Events">
                  <div className="space-y-2">
                    {report.notableEvents.map((ev, i) => (
                      <div key={i} className="p-3 rounded-lg bg-muted/40 border border-border space-y-1 print:break-inside-avoid">
                        <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground print:text-gray-500">
                          <Clock className="h-3 w-3" />
                          {ev.datetime ? new Date(ev.datetime).toLocaleString() : "N/A"}
                        </div>
                        <p className="text-sm text-foreground/85 print:text-black">{ev.what}</p>
                        <p className="text-xs text-primary/70 print:text-blue-700">
                          <strong>Why it matters:</strong> {ev.whyItMatters}
                        </p>
                      </div>
                    ))}
                  </div>
                </Section>
              )}

              {/* ── 6. Visualizations ── */}
              <Section num="06" title="Suggested Visualizations">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 print:grid-cols-3">
                  {report.visualizations.map((viz, i) => {
                    const VizIcon = vizIcon[viz.type] ?? BarChart3;
                    return (
                      <div key={i} className="p-4 rounded-lg bg-muted/40 border border-border space-y-2 print:break-inside-avoid">
                        <div className="flex items-center gap-2">
                          <VizIcon className="h-4 w-4 text-primary" />
                          <span className="text-xs font-mono font-semibold text-foreground/80 print:text-black">{viz.title}</span>
                        </div>
                        <p className="text-xs text-muted-foreground leading-relaxed print:text-gray-500">{viz.description}</p>
                      </div>
                    );
                  })}
                </div>
              </Section>

              {/* ── 7. Recommendations ── */}
              <Section num="07" title="Remediation & Recommendations">
                <div className="space-y-2">
                  {report.recommendations.map((rec, i) => (
                    <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-muted/40 border border-border print:break-inside-avoid">
                      <ArrowRight className="h-4 w-4 text-primary shrink-0 mt-0.5" />
                      <div className="space-y-1 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium text-foreground/90 print:text-black">{rec.action}</span>
                          <span className={`text-[10px] font-mono font-bold uppercase px-1.5 py-0.5 rounded border ${
                            rec.priority === "Immediate"
                              ? "text-red-400 bg-red-400/10 border-red-400/30"
                              : rec.priority === "Short-term"
                                ? "text-yellow-400 bg-yellow-400/10 border-yellow-400/30"
                                : "text-green-400 bg-green-400/10 border-green-400/30"
                          }`}>
                            {rec.priority}
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground print:text-gray-500">{rec.rationale}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </Section>

              {/* ── 8. Overall Status ── */}
              <Section num="08" title="Overall System Status">
                <div className={`inline-flex items-center gap-3 px-4 py-3 rounded-lg border ${statusConfig[report.overallStatus].border} ${statusConfig[report.overallStatus].bg}`}>
                  <StatusIcon className={`h-5 w-5 ${statusConfig[report.overallStatus].color}`} />
                  <div>
                    <span className={`font-mono font-bold text-base ${statusConfig[report.overallStatus].color}`}>
                      {report.overallStatus}
                    </span>
                    <p className="text-xs text-muted-foreground mt-0.5 print:text-gray-500">{report.statusJustification}</p>
                  </div>
                </div>
              </Section>

              {/* ── Footer ── */}
              <div className="border-t border-border/50 pt-6 text-center text-xs text-muted-foreground font-mono print:text-gray-400">
                <div className="flex items-center justify-center gap-2 mb-1">
                  <CheckCircle2 className="h-3 w-3 text-primary" />
                  <span>Generated by OmniLog AI Security Assistant</span>
                </div>
                <span>Powered by Claude AI · Graylog SIEM</span>
              </div>
            </div>
          )}
        </div>
      </motion.div>
    </AnimatePresence>,
    document.body
  );
};

export default ReportModal;
