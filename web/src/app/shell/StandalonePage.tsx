import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { Wordmark } from './Wordmark'

/** Plain, undecorated frame for enrol, unlock and the revoked page. */
export function StandalonePage({ children, aside }: { children: ReactNode; aside?: ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col bg-background">
      <header className="flex h-14 items-center justify-between border-b border-rule px-4 sm:px-6">
        <Link to="/" aria-label="QuantumGuard home">
          <Wordmark />
        </Link>
        {aside}
      </header>
      <main className="flex flex-1 items-start justify-center px-4 py-10 sm:py-16">
        <div className="w-full max-w-md">{children}</div>
      </main>
    </div>
  )
}
