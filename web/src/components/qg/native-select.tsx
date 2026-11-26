import * as React from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from 'cn'

export type NativeSelectOption = { value: string; label: string; disabled?: boolean }

type NativeSelectProps = Omit<React.ComponentProps<'select'>, 'value' | 'onChange' | 'children' | 'className'> & {
  value: string
  onValueChange: (value: string) => void
  options: NativeSelectOption[]
  /** Applied to the wrapper: use it for width. */
  className?: string
}

/** A styled native select. A style element rendered at run time is blocked by `style-src 'self'`, so no popup library is used. */
function NativeSelect({ value, onValueChange, options, className, ...props }: NativeSelectProps) {
  return (
    <div className={cn('relative w-full', className)}>
      <select
        data-slot="native-select"
        value={value}
        onChange={(e) => onValueChange(e.target.value)}
        className="h-10 w-full min-w-0 cursor-pointer appearance-none rounded-none border border-input bg-background py-1 pr-8 pl-2.5 text-xs transition-colors outline-none [color-scheme:light] focus-visible:border-ring focus-visible:ring-1 focus-visible:ring-ring/50 disabled:pointer-events-none disabled:cursor-not-allowed disabled:bg-input/50 disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-1 aria-invalid:ring-destructive/20 md:text-xs dark:bg-input/30 dark:[color-scheme:dark] dark:disabled:bg-input/80 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40"
        {...props}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value} disabled={o.disabled}>
            {o.label}
          </option>
        ))}
      </select>
      <ChevronDown aria-hidden="true" className="pointer-events-none absolute top-1/2 right-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
    </div>
  )
}

export { NativeSelect }
