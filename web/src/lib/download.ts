/** Hands a decrypted file to the browser through a one-time object URL. Nothing is kept. */
export function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
  // Revoked as soon as the browser has had a moment to start the download.
  setTimeout(() => URL.revokeObjectURL(url), 1500)
}

export function saveJson(value: unknown, name: string) {
  saveBlob(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }), name)
}
