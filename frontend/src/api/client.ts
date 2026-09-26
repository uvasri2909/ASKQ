// Thin fetch wrapper for the ASKQ backend. Requests are same-origin; in
// development the Vite dev server proxies them to FastAPI.

export interface HealthResponse {
  status: string
  service: string
  version: string
  environment: string
}

export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  const response = await fetch('/health', { signal })
  if (!response.ok) {
    throw new Error(`Backend returned HTTP ${response.status}`)
  }
  return (await response.json()) as HealthResponse
}
