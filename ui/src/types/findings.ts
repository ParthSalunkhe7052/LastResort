export interface FindingRecord {
  id: string
  scanId: string
  title: string
  description: string
  severity: string
  vulnerabilityType: string
  endpoint: string
  payload: string
  responseStatus: number
  confidence: number
  isFalsePositive: boolean
  createdAt: string
  category: string
}
