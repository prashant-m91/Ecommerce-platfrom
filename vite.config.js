import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import crypto from "crypto";
import fs from "fs";
import path from "path";

// https://vitejs.dev/config/
export default defineConfig({
	plugins: [react()],
	// Development server customizations
	configureServer(server) {
			// Add a middleware that generates a per-request nonce and sets a CSP header
			// that permits only scripts/styles having that nonce. This improves security
			// in development while still allowing libraries that need inline styles if
			// you explicitly add the nonce to those elements.
			server.middlewares.use((req, res, next) => {
				try {
					const nonce = crypto.randomBytes(16).toString("base64");

					// Construct a development-friendly CSP that references the nonce for
					// inline styles/scripts and still allows required external hosts.
							const csp = [
								"default-src 'self'",
								`script-src 'self' 'nonce-${nonce}' https://js.stripe.com https://m.stripe.network https://cdn.clerk.com https://clerk.com https://cdn.jsdelivr.net https://unpkg.com 'unsafe-eval'`,
								// Stricter style-src: remove 'unsafe-inline' so element.style and
								// style attributes will be blocked unless explicitly handled.
								`style-src 'self' 'nonce-${nonce}' https://m.stripe.network`,
								"connect-src 'self' https://api.stripe.com https://m.stripe.network",
								"img-src 'self' data: https://*.stripe.com",
								"frame-src 'self' https://js.stripe.com https://m.stripe.network",
							].join('; ');

					res.setHeader('Content-Security-Policy', csp);

					// If the request is for the document root, replace the placeholder nonce so
					// inline elements in the HTML can reference the same nonce value.
					if (req.url === '/' || req.url === '/index.html') {
						const indexPath = path.resolve(process.cwd(), 'index.html');
						if (fs.existsSync(indexPath)) {
							let html = fs.readFileSync(indexPath, 'utf8');
							html = html.replace(/%CSP_NONCE%/g, nonce);
							res.setHeader('Content-Type', 'text/html');
							return res.end(html);
						}
					}

					// Make the nonce available to downstream handlers via header if needed
					res.setHeader('X-CSP-Nonce', nonce);
				} catch (err) {
					// If anything fails, continue without nonce (dev only)
					console.error('Failed to generate CSP nonce:', err);
				}
				next();
			});
	},
	server: {
		proxy: {
			"/api": {
				target: "http://localhost:3003",
				changeOrigin: true,
				secure: false, // allow self-signed or unverifiable certs in dev proxy
				ws: true,
			},
		},
	},
});
