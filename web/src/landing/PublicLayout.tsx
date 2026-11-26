import { ArrowRight, GitBranch } from 'lucide-react'
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { Wordmark } from '@/app/shell/Wordmark'
import { Button } from '@/components/ui/button'
import { LINKS } from './links'

const NAV = [
  { to: '/how-it-works', label: 'How it works' },
  { to: '/product', label: 'Product' },
  { to: '/architecture', label: 'Architecture' },
  { to: '/security', label: 'Security' },
  { to: '/docs', label: 'Docs' },
]

/** Frame for the public pages: static, no backend calls, readable without an account. */
export function PublicLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col bg-background">
      <a href="#content" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:bg-primary focus:px-3 focus:py-2 focus:text-primary-foreground">
        Skip to content
      </a>
      <header className="sticky top-0 z-30 border-b border-rule bg-background/95 backdrop-blur-sm">
        <div className="mx-auto flex h-14 max-w-[1120px] items-center gap-6 px-4 sm:px-6">
          <Link to="/" aria-label="QuantumGuard home">
            <Wordmark />
          </Link>
          <nav aria-label="Site" className="flex flex-1 items-center gap-5 overflow-x-auto max-md:hidden">
            {NAV.map((n) => (
              <Link key={n.to} to={n.to} className="whitespace-nowrap text-muted-foreground hover:text-foreground">
                {n.label}
              </Link>
            ))}
            {LINKS.repo ? (
              <a href={LINKS.repo} rel="noreferrer" className="inline-flex items-center gap-1.5 whitespace-nowrap text-muted-foreground hover:text-foreground" data-testid="nav-github">
                <GitBranch className="size-4" aria-hidden />
                GitHub
              </a>
            ) : null}
          </nav>
          <Button asChild className="ml-auto h-9" data-testid="launch-console">
            <Link to="/app">
              Launch console
              <ArrowRight aria-hidden />
            </Link>
          </Button>
        </div>
        <nav aria-label="Site sections" className="flex gap-4 overflow-x-auto border-t border-border px-4 py-2 md:hidden">
          {NAV.map((n) => (
            <Link key={n.to} to={n.to} className="whitespace-nowrap text-sm text-muted-foreground">
              {n.label}
            </Link>
          ))}
        </nav>
      </header>
      <main id="content" className="flex-1">
        {children}
      </main>
      <footer className="border-t border-rule">
        <div className="mx-auto flex max-w-[1120px] flex-col gap-4 px-4 py-8 sm:px-6 md:flex-row md:items-start md:justify-between">
          <div className="max-w-sm">
            <Wordmark />
            <p className="mt-2 text-sm text-muted-foreground">
              A research prototype. Synthetic data only. Not audited; read the limits before relying on it.
            </p>
          </div>
          <ul className="grid grid-cols-2 gap-x-10 gap-y-1.5 text-sm">
            {LINKS.repo ? (
              <li>
                <a className="hover:text-primary hover:underline" href={LINKS.repo} rel="noreferrer">
                  GitHub repository
                </a>
              </li>
            ) : null}
            {LINKS.brief ? (
              <li>
                <a className="hover:text-primary hover:underline" href={LINKS.brief} rel="noreferrer">
                  Project brief (PDF)
                </a>
              </li>
            ) : null}
            {LINKS.video ? (
              <li>
                <a className="hover:text-primary hover:underline" href={LINKS.video} rel="noreferrer">
                  Demo video
                </a>
              </li>
            ) : null}
            <li>
              <Link className="hover:text-primary hover:underline" to="/#limits">
                Threat model and limits
              </Link>
            </li>
            <li>
              <Link className="hover:text-primary hover:underline" to="/docs">
                API reference
              </Link>
            </li>
            <li>
              <Link className="hover:text-primary hover:underline" to="/status">
                Status
              </Link>
            </li>
            <li>
              <Link className="hover:text-primary hover:underline" to="/docs#notices">
                Third-party notices
              </Link>
            </li>
          </ul>
        </div>
      </footer>
    </div>
  )
}
