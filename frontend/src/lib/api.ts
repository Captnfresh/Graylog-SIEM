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
}

export interface ChatResponse {
  content: string
  analysis: ThreatAnalysis
  logs_queried: number
}

export interface StatsResponse {
  failedLogins: number
  errors: number
  networkActivity: number
  suspiciousBehaviour: number
  riskScore: number
  activeAlerts: number
}

export async function sendChatMessage(message: string): Promise<ChatResponse> {
  const res = await fetch(`${API_BASE}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  })
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`API error ${res.status}: ${text}`)
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
