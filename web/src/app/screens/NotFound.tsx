import { Link } from 'react-router'
import { StandalonePage } from '@/app/shell/StandalonePage'
import { EmptyState } from '@/components/qg/page'
import { Button } from '@/components/ui/button'
import { useDocumentTitle } from '@/lib/hooks'

export default function NotFound({ standalone = false }: { standalone?: boolean }) {
  useDocumentTitle('Page not found')
  const body = (
    <EmptyState
      title="This page does not exist"
      body="The address may be mistyped, or the page was moved."
      testId="not-found"
      action={
        <Button asChild className="h-9">
          <Link to={standalone ? '/' : '/app'}>{standalone ? 'Go to the home page' : 'Go to the console'}</Link>
        </Button>
      }
    />
  )
  return standalone ? <StandalonePage>{body}</StandalonePage> : body
}
