// Base URL: empty = same origin (nginx proxies /api/* to backend in Docker)
// Set VITE_API_URL=http://localhost:8000 for local dev outside Docker
const API_BASE = import.meta.env.VITE_API_URL ?? ""

export interface LogEntry {
  timestamp: string
  source: string
  level: "INFO" | "WARNING" | "ERROR" | "CRITICAL"
  message: string
}

export interface ThreatAnalysis {
  summary: string
  threatLevel: "Low" | "Medium" | "High" | "Critical"
  affectedSystems: string[]
  recommendedActions: string[]
  logEntries: LogEntry[]
  followUps: string[]
}

export interface HistoryMessage {
  role: "user" | "assistant"
  content: string
}

export interface ChatResponse {
  content: string
  analysis: ThreatAnalysis
  logs_queried: number
}

export interface StreamEvent {
  type: "text" | "done"
  delta?: string
  analysis?: ThreatAnalysis
  logs_queried?: number
}

export interface AlertEvent {
  type: "alert" | "heartbeat"
  riskScore: number
  analysis?: ThreatAnalysis
  logsQueried?: number
}

export interface StatsResponse {
  failedLogins: number
  errors: number
  networkActivity: number
  suspiciousBehaviour: number
  riskScore: number
  activeAlerts: number
}

export async function sendChatMessage(
  message: string,
  history: HistoryMessage[] = []
): Promise<ChatResponse> {
  const res = await fetch(`${API_BASE}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, history }),
  })
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`API error ${res.status}: ${text}`)
  }
  return res.json()
}

export async function* streamChatMessage(
  message: string,
  history: HistoryMessage[] = []
): AsyncGenerator<StreamEvent> {
  const res = await fetch(`${API_BASE}/api/chat/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, history }),
  })

  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`API error ${res.status}: ${text}`)
  }

  const reader = res.body!.getReader()
  const decoder = new TextDecoder()
  let buffer = ""

  while (true) {
    const { done, value } = await reader.read()
    if (done) break

    buffer += decoder.decode(value, { stream: true })
    // SSE events are separated by double newlines
    const parts = buffer.split("\n\n")
    buffer = parts.pop() ?? ""

    for (const part of parts) {
      const line = part.trim()
      if (line.startsWith("data: ")) {
        try {
          yield JSON.parse(line.slice(6)) as StreamEvent
        } catch {
          // malformed event — skip
        }
      }
    }
  }
}

/**
 * Subscribe to the live alert stream. Returns an EventSource.
 * Close it by calling es.close().
 */
export function subscribeToAlerts(
  onAlert: (event: AlertEvent) => void,
  onHeartbeat?: (riskScore: number) => void,
): EventSource {
  const es = new EventSource(`${API_BASE}/api/alerts/stream`)
  es.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data) as AlertEvent
      if (data.type === "alert") onAlert(data)
      else if (data.type === "heartbeat") onHeartbeat?.(data.riskScore)
    } catch {
      // malformed event — ignore
    }
  }
  return es
}

export interface ReportRisk {
  level: "Low" | "Medium" | "High"
  title: string
  description: string
  affectedTime: string
  businessImpact: string
}

export interface ReportEvent {
  datetime: string
  what: string
  whyItMatters: string
}

export interface ReportViz {
  type: "bar" | "line" | "pie"
  title: string
  description: string
}

export interface ReportRecommendation {
  action: string
  priority: "Immediate" | "Short-term" | "Long-term"
  rationale: string
}

export interface SecurityReport {
  executiveSummary: string
  keyInsights: string[]
  risks: ReportRisk[]
  notableEvents: ReportEvent[]
  visualizations: ReportViz[]
  recommendations: ReportRecommendation[]
  overallStatus: "Healthy" | "Needs Attention" | "Critical"
  statusJustification: string
  boardroomSummary: string
  topTakeaways: string[]
  logTimeRange: { earliest: string; latest: string }
  generatedAt: string
}

export async function generateReport(): Promise<SecurityReport> {
  const res = await fetch(`${API_BASE}/api/report`, { method: "POST" })
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`Report error ${res.status}: ${text}`)
  }
  return res.json()
}

export async function fetchStats(): Promise<StatsResponse> {
  const res = await fetch(`${API_BASE}/api/stats`)
  if (!res.ok) throw new Error(`Stats error ${res.status}`)
  return res.json()
}

export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/api/health`, {
      signal: AbortSignal.timeout(4000),
    })
    const data = await res.json()
    return data.status === "ok"
  } catch {
    return false
  }
}
