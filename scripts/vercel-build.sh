#!/usr/bin/env bash
#
# Vercel build for the Heritage Bank static frontend.
#
# WHY THIS EXISTS
# ---------------
# Vercel resolves `outputDirectory` relative to the project's **Root Directory**
# setting, which lives in the dashboard and is easy to get out of sync with the
# repo. If Root Directory is the repo root, the frontend is at `public/`; if
# someone set Root Directory to `public`, the frontend is at `.`. Hard-coding
# either one breaks the other and produces:
#
#   Error: No Output Directory named "public" found after the Build completed.
#
# So instead of depending on that setting, this script locates the frontend,
# copies it into a directory it is guaranteed to create, and Vercel publishes
# that. Works from either Root Directory.
#
set -euo pipefail

OUT=".vercel-static"

echo "[build] pwd: $(pwd)"
echo "[build] top-level contents:"
ls -1 | head -20

# Locate the frontend: prefer public/, fall back to the current directory.
if [ -f "public/index.html" ]; then
  SRC="public"
elif [ -f "index.html" ]; then
  SRC="."
else
  echo "[build] ERROR: no index.html in ./public or . — cannot locate the frontend."
  echo "[build] Check the Root Directory setting in Vercel project settings."
  exit 1
fi
echo "[build] frontend source: $SRC"

rm -rf "$OUT"
mkdir -p "$OUT"

# Copy the frontend, leaving out server-side code and the output dir itself.
tar -cf - \
  --exclude="./$OUT" \
  --exclude="./backend" \
  --exclude="./functions" \
  --exclude="./node_modules" \
  --exclude="./.git" \
  --exclude="./scripts" \
  -C "$SRC" . | tar -xf - -C "$OUT"

COUNT=$(find "$OUT" -type f | wc -l | tr -d ' ')
echo "[build] copied $COUNT files into $OUT"

if [ ! -f "$OUT/index.html" ]; then
  echo "[build] ERROR: $OUT/index.html missing after copy."
  exit 1
fi
if [ ! -f "$OUT/config.js" ]; then
  echo "[build] WARNING: $OUT/config.js missing — the frontend will not know the API URL."
fi

echo "[build] ✓ output ready at $OUT"
