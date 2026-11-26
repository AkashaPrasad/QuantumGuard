// A drop-in for the `react-style-singleton` module, wired through an alias in vite.config.ts.
//
// The original creates a <style> element at run time (it is how the dialog scroll lock adds
// its body rule). Our Content-Security-Policy is `style-src 'self'`, which blocks that element.
// This version applies the same CSS text through a constructed stylesheet, which the policy
// does not restrict, so the scroll lock works and nothing has to be allowed inline.
// Same three exports and the same behaviour: one shared sheet, added on first use, removed on last.
import { useEffect } from 'react'

function makeSheet() {
  let users = 0
  let sheet: CSSStyleSheet | null = null
  return {
    add(css: string) {
      if (users === 0) {
        sheet = new CSSStyleSheet()
        sheet.replaceSync(css)
        document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet]
      }
      users++
    },
    remove() {
      users = Math.max(users - 1, 0)
      if (users === 0 && sheet) {
        const gone = sheet
        document.adoptedStyleSheets = document.adoptedStyleSheets.filter((s) => s !== gone)
        sheet = null
      }
    },
  }
}

export const stylesheetSingleton = makeSheet

export const styleHookSingleton = () => {
  const sheet = makeSheet()
  return (styles: string, isDynamic?: boolean) => {
    useEffect(() => {
      sheet.add(styles)
      return () => sheet.remove()
      // Matches the original: re-apply only when the styles are marked dynamic and change.
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [styles && isDynamic])
  }
}

export const styleSingleton = () => {
  const useStyle = styleHookSingleton()
  const Sheet = ({ styles, dynamic }: { styles: string; dynamic?: boolean }) => {
    useStyle(styles, dynamic)
    return null
  }
  return Sheet
}
