import { driver } from 'driver.js'
import type { Config, Driver, DriveStep } from 'driver.js'
import { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router'
import { stepsFor } from './steps'
import type { TourId, TourStep } from './steps'
import { useMe } from '../app/client-context'
import './tour.css'

const SEEN_KEY = 'qg-tour-seen'
const WAIT_MS = 1500

function roleKey(roles: string[]): string {
  return [...roles].sort().join('+') || 'none'
}

function readSeen(): string[] {
  try {
    const raw = window.localStorage.getItem(SEEN_KEY)
    const parsed: unknown = raw ? JSON.parse(raw) : []
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : []
  } catch {
    return []
  }
}

function markSeen(key: string): void {
  try {
    const seen = readSeen()
    if (!seen.includes(key)) window.localStorage.setItem(SEEN_KEY, JSON.stringify([...seen, key]))
  } catch {
    // Display preference only; the tour can be offered again.
  }
}

const selector = (anchor: string) => `[data-tour="${anchor}"]`

/** Starts the guided tour: once per role set on the first unlocked session, and whenever `qg:start-tour` is dispatched. */
export function Tour() {
  const { state, roles } = useMe()
  const navigate = useNavigate()
  const navigateRef = useRef(navigate)
  const rolesRef = useRef(roles)
  const active = useRef<Driver | null>(null)
  const unlocked = state.kind === 'unlocked'
  const key = roleKey(roles)

  useEffect(() => {
    navigateRef.current = navigate
    rolesRef.current = roles
  })

  useEffect(() => {
    if (!unlocked) return
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    const stop = () => {
      active.current?.destroy()
      active.current = null
    }

    const start = (tour: TourId) => {
      stop()
      const steps: TourStep[] = stepsFor(tour, rolesRef.current)
      if (steps.length === 0) return
      const demo = tour === 'lose-a-device'
      const returnTo = document.activeElement instanceof HTMLElement ? document.activeElement : null

      // Go to the page the target step belongs to, unless its anchor is already on screen.
      const ensureRoute = (step: TourStep | undefined) => {
        if (!step?.route || document.querySelector(selector(step.anchor))) return
        if (window.location.pathname !== step.route) void navigateRef.current(step.route)
      }

      const driveSteps: DriveStep[] = steps.map((s, i) => ({
        element: selector(s.anchor),
        popover: {
          title: s.title,
          description: s.text,
          side: s.side ?? 'bottom',
          align: 'start',
          showButtons: i === 0 ? ['next', 'close'] : ['next', 'previous', 'close'],
          nextBtnText: i === steps.length - 1 ? 'Done' : 'Next',
        },
      }))

      const config: Config = {
        steps: driveSteps,
        animate: !reduce,
        smoothScroll: !reduce,
        showProgress: true,
        progressText: '{{current}} of {{total}}',
        prevBtnText: 'Back',
        closeBtnLabel: 'Skip tour',
        allowClose: true,
        allowKeyboardControl: true,
        overlayClickBehavior: 'none',
        // Steps whose anchor is not on the page wait for it, then are skipped.
        waitForElement: WAIT_MS,
        skipMissingElement: true,
        // The demo never clicks for the person and must leave the page and its dialogs usable.
        disableActiveInteraction: !demo,
        overlayOpacity: demo ? 0 : 0.55,
        stagePadding: 6,
        stageRadius: 0,
        popoverClass: 'qg-tour',
        onPopoverRender: (popover) => {
          popover.closeButton.textContent = 'Skip tour'
        },
        onNextClick: (_el, _step, { driver: d, index }) => {
          if (d.isLastStep()) return d.destroy()
          ensureRoute(steps[(index ?? 0) + 1])
          d.moveNext()
        },
        onPrevClick: (_el, _step, { driver: d, index }) => {
          ensureRoute(steps[(index ?? 0) - 1])
          d.movePrevious()
        },
        onDestroyed: (_el, _step, { reason }) => {
          document.documentElement.classList.remove('qg-tour-demo')
          if (reason === 'replaced') return
          active.current = null
          if (returnTo?.isConnected) returnTo.focus({ preventScroll: true })
        },
      }

      const d = driver(config)
      active.current = d
      document.documentElement.classList.toggle('qg-tour-demo', demo)
      ensureRoute(steps[0])
      d.drive(0)
    }

    const onStart = (e: Event) => {
      const detail = (e as CustomEvent<unknown>).detail
      start(detail === 'lose-a-device' ? 'lose-a-device' : 'role')
    }
    window.addEventListener('qg:start-tour', onStart)

    // First unlocked session for this set of roles: wait a moment for the page to draw.
    let timer: number | undefined
    if (!readSeen().includes(key)) {
      timer = window.setTimeout(() => {
        markSeen(key)
        start('role')
      }, 700)
    }

    return () => {
      window.removeEventListener('qg:start-tour', onStart)
      window.clearTimeout(timer)
      stop()
    }
  }, [unlocked, key])

  return null
}
