#!/bin/bash
set -e

echo "🏗️ Building Heritage Bank for Render (Frontend + Backend)..."

# Install root dependencies (if any)
echo "📦 Installing root dependencies..."
npm install --omit=dev || true

# Install backend dependencies
echo "📦 Installing backend dependencies..."
npm install --prefix backend --omit=dev

# Build step (if needed in future)
echo "✅ Build complete!"
echo "✓ Frontend assets ready from root directory"
echo "✓ Backend API ready from backend/server.js"
echo "✓ Server will serve static files + API endpoints"
