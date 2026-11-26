// Outbound links are set at build time so no address is hard-coded in the source.
// Unset links are simply not rendered.
const env = import.meta.env
export const LINKS = {
  repo: (env.VITE_QG_REPO_URL as string | undefined) || null,
  brief: (env.VITE_QG_BRIEF_URL as string | undefined) || null,
  video: (env.VITE_QG_VIDEO_URL as string | undefined) || null,
}
