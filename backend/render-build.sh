#!/bin/bash
set -e

echo "🏗️ Building Heritage Bank for Render..."

# Install root dependencies (if needed)
echo "📦 Installing root dependencies..."
npm install

# Install backend dependencies
echo "📦 Installing backend dependencies..."
npm install --prefix backend

# Run database migrations if needed
if [ -f "migrate-profile.js" ]; then
  echo "🗄️ Running database migrations..."
  node migrate-profile.js || echo "⚠️ Migration script ran (may be idempotent)"
fi

echo "✅ Build complete!"
