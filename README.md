# Backend - E-commerce (AI additions)

This backend now includes two AI endpoints (examples):

- `POST /api/ai/chat` - proxied chat to configured Gemini-like API. Body: `{ message: string, sessionId?: string }`.
- `POST /api/ai/recommend` - asks the AI to recommend product ids. Body: `{ context?: string, userId?: string }`.

Configuration:

1. Copy `.env.example` to `.env` and fill in `GEMINI_API_KEY` and other values.
2. `npm install` in `backend/` to install `axios` (already added to `package.json`).
3. Start server: `npm run dev`.

Notes:
- The Gemini client is a lightweight wrapper in `lib/gemini.js`. It expects a Bearer API key.
- Responses from AI are not fully validated/normalized — treat them as helper suggestions until you add stricter parsing.
 - If `GEMINI_API_KEY` is missing or the Gemini call fails, the endpoints provide safe fallbacks:
	 - `POST /api/ai/chat` returns a canned support reply and `fallback: true` in the response.
	 - `POST /api/ai/recommend` returns up to 4 real products selected randomly if the AI cannot return structured ids.
