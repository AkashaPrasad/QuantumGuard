#!/usr/bin/env bash
# Build brief/brief.pdf (A4, exactly two pages) from brief/brief.md with pinned container images.
# Only Docker is needed on the host. Exits non-zero unless the PDF has two pages and the line that
# mentions the demo video carries an https:// link. A PDF that fails a check is kept as
# brief/brief.draft.pdf and is never written to brief/brief.pdf.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/image-lib.sh"
cd "$QG_ROOT"
source_file=brief/brief.md
[[ -f $source_file ]] || { printf 'brief: %s not found.\n' "$source_file" >&2; exit 2; }
pandoc_image=$(image_value PANDOC_IMAGE)
chrome_image=$(image_value CHROME_IMAGE)
python_image=$(image_value PYTHON_IMAGE)

work=$(mktemp -d)
chmod 755 "$work"
trap 'rm -rf -- "$work"' EXIT
cp -- "$source_file" "$work/brief.md"
cat > "$work/style.html" <<'CSS'
<style>
  @page { size: A4; margin: 11mm 13mm; }
  html, body { font-size: 8.3pt !important; }
  body { font-family: "Open Sans", "FreeSans", sans-serif; line-height: 1.32; color: #111; margin: 0; max-width: none; padding: 0; }
  h1 { font-size: 15pt; font-weight: bold; margin: 0 0 4pt; }
  h2 { font-size: 10.5pt; font-weight: bold; margin: 8pt 0 3pt; }
  p, ul { margin: 3pt 0; }
  ul { padding-left: 14pt; }
  li { margin: 1.5pt 0; }
  table { border-collapse: collapse; width: 100%; margin: 4pt 0; font-size: 7.2pt; }
  th, td { border: 0.5pt solid #888; padding: 1.5pt 4pt; text-align: left; vertical-align: top; }
  th { background: #eee; }
  pre { font-size: 7.4pt; line-height: 1.2; background: #f4f4f4; padding: 4pt; margin: 4pt 0; overflow: hidden; }
  code { font-family: "FreeMono", monospace; font-size: 0.9em; }
  tr { break-inside: avoid; }
  a { color: #0645ad; }
</style>
CSS

docker run --rm --platform linux/amd64 --network none --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" --mount "type=bind,src=$work,dst=/work" --workdir /work "$pandoc_image" \
    -f gfm -t html5 --standalone --metadata pagetitle="QuantumGuard brief" \
    --include-in-header=style.html -o brief.html brief.md

docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" -e HOME=/tmp --tmpfs /tmp:rw,mode=1777 \
    --mount "type=bind,src=$work,dst=/work" --entrypoint chromium-browser "$chrome_image" \
    --no-sandbox --disable-gpu --headless --no-pdf-header-footer --disable-crash-reporter \
    --print-to-pdf=/work/brief.pdf file:///work/brief.html >/dev/null 2>&1
[[ -s $work/brief.pdf ]] || { printf 'brief: PDF rendering produced no file.\n' >&2; exit 1; }

pages=$(docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
    --mount "type=bind,src=$work,dst=/work,readonly" "$python_image" python -c '
import re, sys
data = open("/work/brief.pdf", "rb").read()
print(len(re.findall(rb"/Type\s*/Page(?![s\w])", data)))')

status=0
if [[ $pages != 2 ]]; then
    printf 'brief: FAIL: the PDF has %s pages, expected exactly 2. Adjust the content or the page-break marker.\n' "$pages" >&2
    status=1
fi
# Every line that mentions the demo video must carry a real https:// link.
video_lines=$(grep -i 'demo video' "$source_file" || true)
if [[ -z $video_lines ]]; then
    printf 'brief: FAIL: no line in %s mentions the demo video.\n' "$source_file" >&2
    status=1
elif grep -Eq 'VIDEO_URL|REPOSITORY_URL' "$source_file"; then
    printf 'brief: FAIL: replace the VIDEO_URL placeholder in %s with the public link to the demo video.\n' "$source_file" >&2
    status=1
elif [[ -n $(printf '%s\n' "$video_lines" | grep -iv 'https://[^[:space:])]' || true) ]]; then
    printf 'brief: FAIL: the line that mentions the demo video has no https:// link (replace the VIDEO_URL and REPOSITORY_URL placeholders in %s).\n' "$source_file" >&2
    status=1
fi

if [[ $status -eq 0 ]]; then
    cp -- "$work/brief.pdf" brief/brief.pdf
    printf 'brief: wrote brief/brief.pdf (%s pages, A4).\n' "$pages"
else
    cp -- "$work/brief.pdf" brief/brief.draft.pdf
    printf 'brief: draft with %s pages kept as brief/brief.draft.pdf; brief/brief.pdf not written.\n' "$pages" >&2
fi
exit "$status"
