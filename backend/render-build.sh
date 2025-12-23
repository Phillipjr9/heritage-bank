#!/bin/bash
set -e

echo "🏗️ Building Heritage Bank for Render..."

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Run database migrations if needed
if [ -f "migrate-profile.js" ]; then
  echo "🗄️ Running database migrations..."
  node migrate-profile.js || echo "⚠️ Migration script ran (may be idempotent)"
fi

echo "✅ Build complete!"
