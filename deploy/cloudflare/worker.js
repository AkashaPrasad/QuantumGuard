// The web edge: static files come straight from the asset store; /api/* and /healthz are forwarded to the API.
// The browser only ever talks to one origin, so the console's strict Content-Security-Policy holds unchanged.

const UNAVAILABLE = JSON.stringify({
  error: {
    code: 'QG_UNAVAILABLE_FAIL_CLOSED',
    message: 'The server could not be reached. Nothing was released.',
    reason: 'edge_upstream',
    request_id: null,
    receipt_id: null,
  },
})

function unavailable() {
  return new Response(UNAVAILABLE, {
    status: 503,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' },
  })
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    if (url.pathname !== '/healthz' && !url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request)
    if (!env.ORIGIN_URL || !env.EDGE_KEY) return unavailable()

    const headers = new Headers(request.headers)
    // Set, never pass through: a caller must not be able to supply these.
    headers.set('X-QG-Edge-Key', env.EDGE_KEY)
    headers.set('X-QG-Client-IP', request.headers.get('CF-Connecting-IP') ?? '')
    headers.delete('X-Forwarded-For')

    let upstream
    try {
      upstream = await fetch(env.ORIGIN_URL + url.pathname + url.search, {
        method: request.method,
        headers,
        body: request.body,
        redirect: 'manual',
      })
    } catch {
      return unavailable()
    }
    // A gateway error page from the path in between is not an API answer; give the console the API's own shape.
    const type = upstream.headers.get('content-type') ?? ''
    if (upstream.status >= 502 && !type.startsWith('application/json')) return unavailable()
    return upstream
  },
}
