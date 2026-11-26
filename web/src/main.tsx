import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router'
import { ClientProvider } from './app/client-context'
import { ErrorBoundary } from './app/ErrorBoundary'
import { AppRoutes } from './app/routes'
import { ThemeProvider } from './app/theme'
import { QgError } from './client/client'
import type { QgClient } from './client/client'
import { ToastProvider } from './components/qg/toast'
import './index.css'

async function loadClient(): Promise<QgClient> {
  // The in-memory stand-in is reachable only from a development server started with VITE_QG_MOCK=1.
  if (import.meta.env.DEV && import.meta.env.VITE_QG_MOCK) {
    const { createMockClient } = await import('./client/mock')
    const persona = new URLSearchParams(location.search).get('persona')
    const client = createMockClient(
      persona === 'none' || persona === 'aiko' || persona === 'mira' || persona === 'priya' || persona === 'jonas' ? { persona } : undefined,
    )
    ;(window as unknown as { __qgMock: unknown }).__qgMock = client.control
    return client
  }
  const real = import.meta.glob<{ createRealClient: () => QgClient }>('./client/real/index.ts')
  const load = real['./client/real/index.ts']
  if (!load) throw new Error('The QuantumGuard client is missing from this build.')
  return (await load()).createRealClient()
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      refetchOnWindowFocus: false,
      // Refusals are answers, not glitches: only a lost connection is worth a second try.
      retry: (count, err) => err instanceof QgError && err.code === 'QG_OFFLINE' && count < 2,
    },
  },
})

void loadClient().then((client) => {
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <ThemeProvider>
        <QueryClientProvider client={queryClient}>
          <ClientProvider client={client}>
            <ToastProvider>
              <BrowserRouter>
                <ErrorBoundary>
                  <AppRoutes />
                </ErrorBoundary>
              </BrowserRouter>
            </ToastProvider>
          </ClientProvider>
        </QueryClientProvider>
      </ThemeProvider>
    </StrictMode>,
  )
})
