import express from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
// Clerk middleware is imported dynamically later after we verify environment variables
import path from "path";
import { fileURLToPath } from "url"; // Needed for ES modules (__dirname)
import authRoutes from "./routes/auth.route.js";
import productRoutes from "./routes/product.route.js";
import cartRoutes from "./routes/cart.route.js";
import couponRoutes from "./routes/coupon.route.js";
import paymentRoutes from "./routes/payment.route.js";
import analyticsRoutes from "./routes/analytics.route.js";
import adminRoutes from "./routes/admin.route.js";
import orderRoutes from "./routes/order.route.js";
import feedbackRoutes from "./routes/feedback.route.js";
import aiRoutes from "./routes/ai.route.js";
import connectDB from "./lib/db.js";

dotenv.config();
connectDB();

// Debug: print effective CLIENT_URL so developers can confirm the backend will
// generate success/cancel redirect URLs that point to the running frontend.
console.log("Effective CLIENT_URL:", process.env.CLIENT_URL || process.env.VITE_CLIENT_URL || "http://localhost:5173");

const app = express();
const PORT = process.env.PORT || 3003;

// Convert import.meta.url to __dirname equivalent for ES module scope
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());

// Clerk middleware attaches auth/session info to incoming requests (req.auth)
// and must be mounted before routes that rely on authentication.

// CORS middleware for development: allow frontend dev server to access API with credentials
app.use(async (req, res, next) => {
  // Echo the request origin when available so local dev ports (5173/5174/etc.) are allowed.
  const origin = req.headers.origin;
  const allowedOrigin = process.env.FRONTEND_ORIGIN || origin || "http://localhost:5173";
  res.header("Access-Control-Allow-Origin", allowedOrigin);
  // Inform caches that Access-Control-Allow-Origin varies by origin
  res.header("Vary", "Origin");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");

  // Handle preflight
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

// Serve static files depending on environment
if (process.env.NODE_ENV === "production") {
  // In production, serve the built frontend
  app.use(express.static(path.join(__dirname, "../frontend/dist")));
} else {
  // In development, serve static assets from public folder
  app.use(express.static(path.join(__dirname, "../public")));
}

// Content Security Policy
app.use(async (req, res, next) => {
  // Content Security Policy
    // For development, generate a per-request nonce and allow inline scripts/styles
    // only if they include the same nonce. This reduces reliance on 'unsafe-inline'.
    try {
      const crypto = await import('crypto');
      const nonce = crypto.randomBytes(16).toString('base64');

    const csp = [
      "default-src 'self'",
      `script-src 'self' 'nonce-${nonce}' https://js.stripe.com https://m.stripe.network https://cdn.clerk.com https://clerk.com https://cdn.jsdelivr.net https://unpkg.com 'unsafe-eval'`,
      `style-src 'self' 'nonce-${nonce}' https://m.stripe.network`,
      "connect-src 'self' https://api.stripe.com https://m.stripe.network",
      "img-src 'self' data: https://*.stripe.com",
      "frame-src 'self' https://js.stripe.com https://m.stripe.network"
    ].join('; ');

    res.setHeader('Content-Security-Policy', csp);
    // Expose nonce via header so server-rendered templates can access it if needed
    res.setHeader('X-CSP-Nonce', nonce);

    // Store the nonce on the response object so the fallback HTML handler can
    // replace the placeholder in index.html with the active nonce.
    res.locals.cspNonce = nonce;
  } catch (err) {
    // If crypto import fails, set a relaxed dev CSP as fallback
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-eval' https://js.stripe.com https://m.stripe.network https://cdn.clerk.com https://clerk.com https://cdn.jsdelivr.net https://unpkg.com; frame-src 'self' https://js.stripe.com https://m.stripe.network; connect-src 'self' https://api.stripe.com https://m.stripe.network; img-src 'self' data: https://*.stripe.com; style-src 'self' 'unsafe-inline' https://m.stripe.network 'unsafe-hashes';"
    );
  }
  next();
});

// Start-up: mount Clerk middleware (if configured), register routes, then start server.
async function init() {
  // Conditionally import and mount Clerk middleware so missing env vars don't crash startup
  const clerkApiKey = process.env.CLERK_API_KEY;
  const clerkPublishableKey = process.env.CLERK_PUBLISHABLE_KEY || process.env.VITE_CLERK_PUBLISHABLE_KEY;
  const clerkSecretKey = process.env.CLERK_SECRET_KEY || process.env.CLERK_API_SECRET || process.env.CLERK_JWT;

  // Only mount Clerk middleware when all required Clerk secrets/keys are present.
  // Some Clerk SDKs require a server-side secret; avoid mounting if it's missing.
  if (clerkApiKey && clerkPublishableKey && clerkSecretKey) {
    try {
      const { clerkMiddleware } = await import("@clerk/express");
      app.use(clerkMiddleware());
      console.log("Clerk middleware mounted");
    } catch (err) {
      console.error("Failed to import/mount Clerk middleware:", err);
    }
  } else {
    console.warn("Clerk keys incomplete; skipping Clerk middleware. Set CLERK_API_KEY, CLERK_PUBLISHABLE_KEY and server secret (CLERK_SECRET_KEY) in .env to enable Clerk.");
  }

  // API routes
  app.use("/api/auth", authRoutes);
  app.use("/api/products", productRoutes);
  app.use("/api/cart", cartRoutes);
  app.use("/api/coupons", couponRoutes);
  app.use("/api/payments", paymentRoutes);
  app.use("/api/analytics", analyticsRoutes);
  app.use("/api/admin", adminRoutes);
  app.use("/api/orders", orderRoutes);
  app.use("/api/feedbacks", feedbackRoutes);
  // AI endpoints for chat and recommendations
  app.use("/api/ai", aiRoutes);

  // Development-only debug endpoint to inspect Clerk auth on the server side.
  // Returns the output of getAuth(req) and some request metadata. Disabled in production.
  app.get('/api/debug/auth', async (req, res) => {
    if (process.env.NODE_ENV === 'production') {
      return res.status(404).json({ message: 'Not available in production' });
    }

    try {
      const clerk = await import('@clerk/express');
      const { getAuth } = clerk;
      const auth = getAuth ? getAuth(req) : null;
      return res.json({ auth, headers: req.headers, cookies: req.cookies || {} });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to load Clerk debug info', error: err?.message || String(err) });
    }
  });

  // Development-only endpoint to clear all cookies present on the request.
  // This helps when multiple Clerk session cookies from other projects are
  // interfering with local development. It simply issues Set-Cookie headers
  // that expire the cookies the browser sent.
  app.get('/api/debug/clear-cookies', (req, res) => {
    if (process.env.NODE_ENV === 'production') {
      return res.status(404).json({ message: 'Not available in production' });
    }

    try {
      const cookies = req.cookies || {};
      const names = Object.keys(cookies);
      names.forEach((name) => {
        // Clear cookie on the root path; this will instruct the browser to remove it.
        res.clearCookie(name, { path: '/' });
      });
      return res.json({ cleared: names });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to clear cookies', error: err?.message || String(err) });
    }
  });

  // Fallback to index.html for client-side routing
  app.get("*", async (req, res) => {
    const nonce = res.locals?.cspNonce;
    if (process.env.NODE_ENV === "production") {
      return res.sendFile(path.join(__dirname, "../frontend/dist/index.html"));
    }

    // In development, serve the public/index.html but replace the %CSP_NONCE%
    // placeholder with the per-request nonce so inline elements can use it.
    const devIndex = path.join(__dirname, "../public/index.html");
    try {
      const fs = await import('fs');
      let html = fs.readFileSync(devIndex, 'utf8');
      if (nonce) html = html.replace(/%CSP_NONCE%/g, nonce);
      res.setHeader('Content-Type', 'text/html');
      return res.send(html);
    } catch (err) {
      // Fallback to static send if reading fails
      return res.sendFile(path.join(__dirname, "../public/index.html"));
    }
  });

  const server = app.listen(PORT, () => {
    console.log("Server is running on http://localhost:" + PORT);
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`Port ${PORT} is already in use. To free the port, find the process using it and terminate it.`);
      console.error('On Windows: run in an elevated Command Prompt:');
      console.error(`  netstat -ano | findstr :${PORT}`);
      console.error('  taskkill /PID <PID_FROM_PREVIOUS> /F');
      console.error('Or set environment variable PORT to another free port and restart.');
      process.exit(1);
    } else {
      console.error('Server error:', err);
      process.exit(1);
    }
  });
}

init();
