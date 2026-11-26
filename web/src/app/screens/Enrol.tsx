import { ArrowLeft, ArrowRight, Check, CircleDashed, Eye, EyeOff, KeyRound, LoaderCircle } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router'
import type { EnrolStep, LocalDevice } from '@/client/client'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { isCode } from '@/lib/errors'
import { useDocumentTitle, useOnline } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { KeyIssue } from '@/motion/KeyIssue'
import { useClient, useDeviceState } from '../client-context'
import { homeFor } from '../nav'
import { StandalonePage } from '../shell/StandalonePage'

const STEPS = ['Code', 'This device', 'Passphrase'] as const
const MIN_LENGTH = 10

const PROGRESS: { step: EnrolStep; label: string }[] = [
  { step: 'generating_keys', label: 'Keys created on this device' },
  { step: 'proving_possession', label: 'Possession of both private keys proved' },
  { step: 'certificate_issued', label: 'Certificate issued and directory updated' },
  { step: 'sealing_keystore', label: 'Private keys locked under your passphrase' },
  { step: 'session_started', label: 'Session started' },
]

function guessDeviceName(): string {
  const ua = navigator.userAgent
  const os = /iPhone/.test(ua)
    ? 'iPhone'
    : /iPad/.test(ua)
      ? 'iPad'
      : /Android/.test(ua)
        ? 'Android device'
        : /Mac OS X/.test(ua)
          ? 'Mac'
          : /Windows/.test(ua)
            ? 'Windows PC'
            : /Linux/.test(ua)
              ? 'Linux computer'
              : 'Computer'
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'browser'
  return `${os}, ${browser}`
}

function strength(p: string): { score: 0 | 1 | 2 | 3; label: string } {
  if (p.length < MIN_LENGTH) return { score: 0, label: `${MIN_LENGTH - p.length} more ${MIN_LENGTH - p.length === 1 ? 'character' : 'characters'} needed` }
  const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length
  const words = p.trim().split(/\s+/).length
  const points = (p.length >= 16 ? 2 : p.length >= 13 ? 1 : 0) + (kinds >= 3 ? 1 : 0) + (words >= 3 ? 1 : 0)
  if (points >= 3) return { score: 3, label: 'Strong' }
  if (points >= 1) return { score: 2, label: 'Good' }
  return { score: 1, label: 'Acceptable. Longer is better.' }
}

function StepHeader({ current }: { current: number }) {
  return (
    <ol className="mb-8 grid grid-cols-3 gap-2" aria-label="Enrolment steps">
      {STEPS.map((label, i) => {
        const state = i < current ? 'done' : i === current ? 'current' : 'todo'
        return (
          <li
            key={label}
            aria-current={state === 'current' ? 'step' : undefined}
            className={cn('border-t-2 pt-2', state === 'todo' ? 'border-border text-muted-foreground' : 'border-primary')}
          >
            <span className="label-caps flex items-center gap-1">
              {state === 'done' ? <Check className="size-3 text-allow" aria-hidden /> : null}
              Step {i + 1}
            </span>
            <span className={cn('block', state === 'current' && 'font-medium')}>{label}</span>
          </li>
        )
      })}
    </ol>
  )
}

/** Flow: web/flows/enrol-device.md */
export default function Enrol() {
  useDocumentTitle('Enrol this device')
  const client = useClient()
  const state = useDeviceState()
  const navigate = useNavigate()
  const online = useOnline()

  const [step, setStep] = useState(0)
  const [code, setCode] = useState('')
  const [deviceName, setDeviceName] = useState(guessDeviceName)
  const [passphrase, setPassphrase] = useState('')
  const [confirm, setConfirm] = useState('')
  const [show, setShow] = useState(false)
  const [touchedConfirm, setTouchedConfirm] = useState(false)
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState<EnrolStep | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [enrolled, setEnrolled] = useState<LocalDevice | null>(null)
  const firstField = useRef<HTMLInputElement>(null)
  const startedHere = useRef(false)

  useEffect(() => {
    firstField.current?.focus()
  }, [step, running])

  // Arriving with a device already on this browser: this page is not for them.
  if (!startedHere.current && !running && !enrolled && state.kind !== 'none') {
    return <Navigate to={state.kind === 'unlocked' ? homeFor(state.device.roles) : '/app/unlock'} replace />
  }

  const s = strength(passphrase)
  const mismatch = touchedConfirm && confirm.length > 0 && confirm !== passphrase
  const canCreate = s.score > 0 && confirm === passphrase && online

  async function create() {
    if (!canCreate) return
    startedHere.current = true
    setRunning(true)
    setError(null)
    setProgress(null)
    try {
      const device = await client.enrol({ code: code.trim().toUpperCase(), device_name: deviceName.trim(), passphrase }, setProgress)
      setPassphrase('')
      setConfirm('')
      setProgress('session_started')
      setEnrolled(device)
    } catch (err) {
      setError(err)
      setRunning(false)
      // A refused code sends the person back to it, with what they typed kept.
      if (isCode(err, 'QG_INVALID_INPUT') && err.reason === 'invite_invalid') setStep(0)
    }
  }

  function next(e: React.FormEvent) {
    e.preventDefault()
    if (step === 0 && code.trim().length >= 4) {
      setError(null)
      setStep(1)
    } else if (step === 1 && deviceName.trim().length >= 2) setStep(2)
    else if (step === 2) void create()
  }

  if (running || enrolled) {
    const reached = progress ? PROGRESS.findIndex((p) => p.step === progress) : -1
    return (
      <StandalonePage>
        <p className="label-caps">{enrolled ? 'Enrolled' : 'Creating your keys'}</p>
        <h1 className="mt-1 text-2xl">{enrolled ? 'This device is enrolled' : 'Setting up this device'}</h1>
        <p className="mt-2 mb-5 text-muted-foreground">
          {enrolled
            ? `${enrolled.device_name} can now protect and open files for ${enrolled.user_name}.`
            : 'This takes a few seconds. Keep this tab open.'}
        </p>
        <KeyIssue step={progress} />
        <ol className="mt-5 flex flex-col gap-2" data-testid="enrol-progress" aria-live="polite">
          {PROGRESS.map((p, i) => {
            const done = enrolled ? true : i < reached
            const active = !enrolled && i === reached
            return (
              <li key={p.step} data-state={done ? 'done' : active ? 'active' : 'todo'} className={cn('flex items-center gap-2', !done && !active && 'text-muted-foreground')}>
                {done ? (
                  <Check className="size-4 text-allow" aria-hidden />
                ) : active ? (
                  <LoaderCircle className="size-4 animate-spin text-primary" aria-hidden />
                ) : (
                  <CircleDashed className="size-4" aria-hidden />
                )}
                {p.label}
                <span className="sr-only">{done ? ' (done)' : active ? ' (in progress)' : ' (waiting)'}</span>
              </li>
            )
          })}
        </ol>
        {enrolled ? (
          <Button size="lg" className="mt-6 h-10 w-full" onClick={() => navigate(homeFor(enrolled.roles))} data-testid="enrol-done" autoFocus>
            Open the console
            <ArrowRight aria-hidden />
          </Button>
        ) : null}
      </StandalonePage>
    )
  }

  return (
    <StandalonePage
      aside={
        state.kind === 'none' ? null : (
          <Link to="/app/unlock" className="text-sm text-primary underline underline-offset-2">
            Unlock instead
          </Link>
        )
      }
    >
      <h1 className="text-2xl">Enrol this device</h1>
      <p className="mt-2 mb-6 text-muted-foreground">
        Enrolling creates keys that never leave this device. You need a one-time code from an admin.
      </p>
      <StepHeader current={step} />

      <form onSubmit={next} noValidate className="flex flex-col gap-5">
        {error ? <ErrorNotice error={error} testId="enrol-error" /> : null}

        {step === 0 ? (
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="enrol-code">Enrolment code</Label>
            <Input
              ref={firstField}
              id="enrol-code"
              data-testid="enrol-code"
              value={code}
              onChange={(e) => setCode(e.target.value.toUpperCase())}
              autoComplete="one-time-code"
              autoCapitalize="characters"
              spellCheck={false}
              className="data h-11 text-base tracking-[0.12em]"
              aria-describedby="enrol-code-help"
            />
            <p id="enrol-code-help" className="text-sm text-muted-foreground">
              Codes work once and last 15 minutes. Hyphens and capitals do not matter.
            </p>
          </div>
        ) : null}

        {step === 1 ? (
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="enrol-device-name">Name for this device</Label>
            <Input
              ref={firstField}
              id="enrol-device-name"
              data-testid="enrol-device-name"
              value={deviceName}
              onChange={(e) => setDeviceName(e.target.value)}
              maxLength={48}
              className="h-10"
              aria-describedby="enrol-device-help"
            />
            <p id="enrol-device-help" className="text-sm text-muted-foreground">
              This is the name you and your operator will see if the device is ever lost. Make it easy to recognise.
            </p>
          </div>
        ) : null}

        {step === 2 ? (
          <>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="enrol-passphrase">Passphrase</Label>
              <div className="relative">
                <Input
                  ref={firstField}
                  id="enrol-passphrase"
                  data-testid="enrol-passphrase"
                  type={show ? 'text' : 'password'}
                  autoComplete="new-password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  className="h-10 pr-10"
                  aria-describedby="enrol-strength enrol-passphrase-help"
                />
                <button
                  type="button"
                  onClick={() => setShow((v) => !v)}
                  className="absolute inset-y-0 right-0 inline-flex w-10 items-center justify-center text-muted-foreground hover:text-foreground"
                  aria-label={show ? 'Hide passphrase' : 'Show passphrase'}
                  aria-pressed={show}
                >
                  {show ? <EyeOff className="size-4" aria-hidden /> : <Eye className="size-4" aria-hidden />}
                </button>
              </div>
              <div className="flex items-center gap-2" id="enrol-strength" data-testid="enrol-strength" data-score={s.score}>
                <div className="flex gap-1" aria-hidden>
                  {[1, 2, 3].map((n) => (
                    <span key={n} className={cn('h-1 w-8', s.score >= n ? (s.score === 1 ? 'bg-caution' : 'bg-allow') : 'bg-border')} />
                  ))}
                </div>
                <span className={cn('text-sm', s.score === 0 ? 'text-muted-foreground' : s.score === 1 ? 'text-caution' : 'text-allow')}>
                  {passphrase ? s.label : `At least ${MIN_LENGTH} characters`}
                </span>
              </div>
              <p id="enrol-passphrase-help" className="text-sm text-muted-foreground">
                A few unrelated words work well. It is used on this device only and is never sent.
              </p>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="enrol-passphrase-confirm">Repeat the passphrase</Label>
              <Input
                id="enrol-passphrase-confirm"
                data-testid="enrol-passphrase-confirm"
                type={show ? 'text' : 'password'}
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                onBlur={() => setTouchedConfirm(true)}
                aria-invalid={mismatch || undefined}
                aria-describedby={mismatch ? 'enrol-mismatch' : undefined}
                className="h-10"
              />
              {mismatch ? (
                <p id="enrol-mismatch" data-testid="enrol-mismatch" role="alert" className="text-sm text-deny">
                  The two passphrases are different.
                </p>
              ) : null}
            </div>
            <p className="border-l-2 border-rule pl-3 text-sm text-muted-foreground">
              There is no reset. If you forget it, an admin gives you a new code and you enrol this device again; your files stay
              available from your other devices.
            </p>
          </>
        ) : null}

        <div className="flex items-center gap-2">
          {step > 0 ? (
            <Button type="button" variant="outline" size="lg" className="h-10" onClick={() => setStep(step - 1)} data-testid="enrol-back">
              <ArrowLeft aria-hidden />
              Back
            </Button>
          ) : null}
          {step < 2 ? (
            <Button
              type="submit"
              size="lg"
              className="h-10 flex-1"
              data-testid="enrol-next"
              disabled={step === 0 ? code.trim().length < 4 : deviceName.trim().length < 2}
            >
              Continue
              <ArrowRight aria-hidden />
            </Button>
          ) : (
            <Button type="submit" size="lg" className="h-10 flex-1" data-testid="enrol-create" disabled={!canCreate}>
              <KeyRound aria-hidden />
              Create my keys
            </Button>
          )}
        </div>
        {!online ? <p className="text-sm text-muted-foreground">You are offline. Enrolment needs a connection.</p> : null}
      </form>
    </StandalonePage>
  )
}
