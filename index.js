const express = require('express');
const app = express();

app.use(express.json({ limit: '10mb' }));

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const APP_TOKEN         = process.env.APP_TOKEN; // simple gate — set in Railway env vars

if (!ANTHROPIC_API_KEY) {
    console.error('ANTHROPIC_API_KEY environment variable is not set');
    process.exit(1);
}

// Health check — Railway uses this to confirm the service is up
app.get('/health', (_req, res) => res.json({ ok: true }));

// Proxy endpoint — mirrors the Anthropic Messages API
app.post('/v1/messages', async (req, res) => {
    // Reject requests that don't carry the app token (prevents casual abuse)
    if (APP_TOKEN && req.headers['x-app-token'] !== APP_TOKEN) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const upstream = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type':      'application/json',
                'x-api-key':         ANTHROPIC_API_KEY,
                'anthropic-version': req.headers['anthropic-version'] ?? '2023-06-01',
            },
            body: JSON.stringify(req.body),
            // No timeout set — Railway allows long-running requests (handles 3-min plan generation)
        });

        const text = await upstream.text();
        res.status(upstream.status)
           .set('Content-Type', 'application/json')
           .send(text);
    } catch (err) {
        console.error('Upstream error:', err);
        res.status(502).json({ error: 'Bad gateway', detail: err.message });
    }
});

const port = process.env.PORT ?? 3000;
app.listen(port, () => console.log(`WASP Fitness proxy listening on port ${port}`));
