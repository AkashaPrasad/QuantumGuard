import { Component } from 'react'
import type { ErrorInfo, ReactNode } from 'react'

/**
 * Last line of defence for the interface: a rendering error shows a plain page
 * with a way forward instead of a blank screen. Nothing sensitive is displayed;
 * keys stay locked in memory or are gone with the reload.
 */
export class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }

  static getDerivedStateFromError() {
    return { failed: true }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Message and component stack only; never request or key material.
    console.error('interface error:', error.message, info.componentStack?.split('\n').slice(0, 4).join(' '))
  }

  render() {
    if (!this.state.failed) return this.props.children
    return (
      <main className="flex min-h-dvh items-start justify-center bg-background px-4 py-16" data-testid="crash-page" role="alert">
        <div className="w-full max-w-md">
          <h1 className="text-2xl">This page stopped working</h1>
          <p className="mt-2 text-muted-foreground">
            Something in the interface failed. Your files and keys are not affected: nothing was sent, and this device locks when the page reloads.
          </p>
          <button
            type="button"
            onClick={() => location.reload()}
            className="mt-5 inline-flex h-10 items-center bg-primary px-4 font-medium text-primary-foreground hover:bg-primary/85"
          >
            Reload the page
          </button>
        </div>
      </main>
    )
  }
}
