'use strict';

const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { initializeApp, cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const {
    AppStoreServerAPIClient, SignedDataVerifier, Environment, Status,
} = require('@apple/app-store-server-library');

const app = express();
app.disable('x-powered-by');

const FIREBASE_PROJECT_ID = 'wasp-fitness';
const BUNDLE_ID = 'EchoFiveWhiskey.WASP-Fitness';
const APP_APPLE_ID = 6814244360;

// Only the exact string "true" enables Apple Sandbox subscriptions.
// This setting never disables authentication or ownership checks.
const ALLOW_SANDBOX = process.env.ALLOW_SANDBOX_JWS === 'true';

const PRODUCTS = new Set([
    'WASP_Elite_Monthly',
    'WASP_Elite_Yearly',
    'com.echofivewhiskey.wasp.pro.monthly',
    'com.echofivewhiskey.wasp.pro.yearly',
]);

let firebaseAuth;
const appleServices = new Map();

function requiredEnv(name) {
    const value = process.env[name];
    if (!value || !value.trim()) throw new Error(`Missing ${name}`);
    return value;
}

function getFirebaseAuth() {
    if (process.env.FIREBASE_AUTH_EMULATOR_HOST) {
        throw new Error('Firebase emulator forbidden');
    }

    if (!firebaseAuth) {
        const credentials = JSON.parse(
            requiredEnv('FIREBASE_SERVICE_ACCOUNT_JSON')
        );

        if (credentials.project_id !== FIREBASE_PROJECT_ID) {
            throw new Error('Wrong Firebase project');
        }

        firebaseAuth = getAuth(initializeApp({
            credential: cert(credentials),
            projectId: FIREBASE_PROJECT_ID,
        }));
    }

    return firebaseAuth;
}

function getAppleServices(environment) {
    if (!appleServices.has(environment)) {
        const root = fs.readFileSync(
            path.join(__dirname, 'AppleRootCA-G3.cer')
        );

        appleServices.set(environment, {
            verifier: new SignedDataVerifier(
                [root], true, environment, BUNDLE_ID, APP_APPLE_ID
            ),
            client: new AppStoreServerAPIClient(
                requiredEnv('APPLE_PRIVATE_KEY').replace(/\\n/g, '\n'),
                requiredEnv('APPLE_KEY_ID').trim(),
                requiredEnv('APPLE_ISSUER_ID').trim(),
                BUNDLE_ID,
                environment
            ),
        });
    }

    return appleServices.get(environment);
}

function accountTokenForUID(uid) {
    const bytes = createHash('sha256')
        .update(`wasp-fitness:app-account:v1:${uid}`, 'utf8')
        .digest()
        .subarray(0, 16);

    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    const hex = bytes.toString('hex');

    return [
        hex.slice(0, 8),
        hex.slice(8, 12),
        hex.slice(12, 16),
        hex.slice(16, 20),
        hex.slice(20, 32),
    ].join('-');
}

function verifierEnvironment(jws) {
    const parts = jws.split('.');

    if (parts.length !== 3) {
        throw new Error('Invalid JWS');
    }

    const hint = JSON.parse(
        Buffer.from(parts[1], 'base64url').toString('utf8')
    );

    // This untrusted hint selects a verifier only.
    // It NEVER authorizes a request or enables Sandbox access.
    // Apple's signature and the environment must then be verified.
    if (hint.environment === Environment.PRODUCTION) {
        return Environment.PRODUCTION;
    }

    if (hint.environment === Environment.SANDBOX) {
        return Environment.SANDBOX;
    }

    // Local Xcode transactions and all unknown environments are rejected.
    throw new Error('Unsupported environment');
}

function matchesActiveAccount(transaction, expectedToken, environment) {
    return (
        transaction.bundleId === BUNDLE_ID &&
        transaction.environment === environment &&
        transaction.type === 'Auto-Renewable Subscription' &&
        PRODUCTS.has(transaction.productId) &&
        typeof transaction.originalTransactionId === 'string' &&
        /^\d+$/.test(transaction.originalTransactionId) &&
        Number.isFinite(transaction.expiresDate) &&
        transaction.expiresDate > Date.now() &&
        transaction.revocationDate == null &&
        transaction.isUpgraded !== true &&
        typeof transaction.appAccountToken === 'string' &&
        transaction.appAccountToken.toLowerCase() === expectedToken
    );
}

function reject(res, status, code) {
    res.locals.proxyOutcome = code;
    return res.status(status).json({ error: code });
}

async function authorize(req, res, next) {
    res.set('Cache-Control', 'no-store');

    const bearer = /^Bearer\s+(\S+)$/i.exec(
        req.get('authorization') || ''
    );
    const jws = req.get('x-subscription-jws');

    if (!bearer) {
        return reject(res, 401, 'firebase_token_required');
    }

    if (!jws) {
        return reject(res, 401, 'subscription_jws_required');
    }

    let auth;

    try {
        auth = getFirebaseAuth();
    } catch {
        console.error('Firebase configuration unavailable');
        return reject(res, 503, 'authentication_unavailable');
    }

    let identity;

    try {
        identity = await auth.verifyIdToken(bearer[1], true);

        if (!identity.uid) {
            throw new Error('Missing UID');
        }
    } catch {
        return reject(res, 401, 'invalid_firebase_token');
    }

    let environment;

    try {
        environment = verifierEnvironment(jws);
    } catch {
        return reject(res, 403, 'invalid_subscription_jws');
    }

    let apple;

    try {
        apple = getAppleServices(environment);
    } catch {
        console.error('Apple verification configuration unavailable');
        return reject(res, 503, 'subscription_verification_unavailable');
    }

    let supplied;

    try {
        supplied = await apple.verifier.verifyAndDecodeTransaction(jws);

        if (
            supplied.environment !== environment ||
            supplied.bundleId !== BUNDLE_ID ||
            !PRODUCTS.has(supplied.productId)
        ) {
            throw new Error('Invalid subscription');
        }
    } catch {
        return reject(res, 403, 'invalid_subscription_jws');
    }

    // This decision uses the verified Apple-signed environment.
    if (
        supplied.environment === Environment.SANDBOX &&
        !ALLOW_SANDBOX
    ) {
        console.info(JSON.stringify({
            timestamp: new Date().toISOString(),
            environment: supplied.environment,
            productId: supplied.productId,
            outcome: 'sandbox_not_accepted_in_production',
        }));

        return reject(
            res,
            403,
            'sandbox_not_accepted_in_production'
        );
    }

    const expectedToken = accountTokenForUID(identity.uid);

    if (!matchesActiveAccount(supplied, expectedToken, environment)) {
        return reject(
            res,
            403,
            'subscription_not_active_or_not_owned'
        );
    }

    // Query the matching Apple environment for current subscription status.
    let current;

    try {
        current = await apple.client.getAllSubscriptionStatuses(
            supplied.originalTransactionId,
            [Status.ACTIVE]
        );
    } catch {
        console.error('Apple subscription status lookup failed');
        return reject(res, 503, 'subscription_status_unavailable');
    }

    try {
        for (const group of current.data || []) {
            for (const item of group.lastTransactions || []) {
                if (
                    item.status !== Status.ACTIVE ||
                    item.originalTransactionId !==
                        supplied.originalTransactionId ||
                    !item.signedTransactionInfo
                ) {
                    continue;
                }

                const latest =
                    await apple.verifier.verifyAndDecodeTransaction(
                        item.signedTransactionInfo
                    );

                if (
                    latest.originalTransactionId ===
                        supplied.originalTransactionId &&
                    matchesActiveAccount(
                        latest,
                        expectedToken,
                        environment
                    )
                ) {
                    req.verifiedSubscription = {
                        uid: identity.uid,
                        environment,
                        productId: latest.productId,
                    };

                    return next();
                }
            }
        }
    } catch {
        return reject(res, 503, 'subscription_status_unverifiable');
    }

    return reject(res, 403, 'active_owned_subscription_required');
}

function sandboxUsage(uid) {
    // Keep one Node process and one Railway replica for this volume.
    // Never fall back to memory or temporary storage.
    if (
        process.env.RAILWAY_VOLUME_MOUNT_PATH !== '/data' ||
        !fs.statSync('/data').isDirectory()
    ) {
        throw new Error('Persistent volume unavailable');
    }

    const configured = process.env.SANDBOX_DAILY_REQUEST_LIMIT;
    const limit = configured === undefined ? 20 : Number(configured);

    if (!Number.isSafeInteger(limit) || limit < 1) {
        throw new Error('Invalid sandbox limit');
    }

    const day = new Date().toISOString().slice(0, 10);
    const file = '/data/wasp-sandbox-usage-v1.json';

    let state;

    try {
        state = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;

        state = {
            version: 1,
            day,
            counts: {},
            total: 0,
        };
    }

    if (
        state.version !== 1 ||
        typeof state.day !== 'string' ||
        !/^\d{4}-\d{2}-\d{2}$/.test(state.day) ||
        state.day > day ||
        !Number.isSafeInteger(state.total) ||
        state.total < 0 ||
        !state.counts ||
        typeof state.counts !== 'object' ||
        Array.isArray(state.counts)
    ) {
        throw new Error('Invalid usage data');
    }

    for (const [key, count] of Object.entries(state.counts)) {
        if (
            !/^[a-f0-9]{64}$/.test(key) ||
            !Number.isSafeInteger(count) ||
            count < 0
        ) {
            throw new Error('Invalid usage data');
        }
    }

    if (state.day !== day) {
        state.day = day;
        state.counts = {};
    }

    // Store a hash of the Firebase UID, never the raw UID.
    const key = createHash('sha256')
        .update(uid, 'utf8')
        .digest('hex');

    const used = state.counts[key] || 0;

    if (used >= limit) {
        return {
            allowed: false,
            used,
            total: state.total,
        };
    }

    if (state.total >= Number.MAX_SAFE_INTEGER) {
        throw new Error('Counter full');
    }

    state.counts[key] = used + 1;
    state.total += 1;

    // Synchronous updates prevent interleaving within this Node process.
    // Atomic replacement preserves the previous file if writing fails.
    const temporary = `${file}.${randomUUID()}.tmp`;
    let descriptor;

    try {
        descriptor = fs.openSync(temporary, 'wx', 0o600);
        fs.writeFileSync(descriptor, JSON.stringify(state), 'utf8');
        fs.fsyncSync(descriptor);
        fs.closeSync(descriptor);
        descriptor = undefined;

        fs.renameSync(temporary, file);

        const directory = fs.openSync('/data', 'r');

        try {
            fs.fsyncSync(directory);
        } finally {
            fs.closeSync(directory);
        }
    } finally {
        if (descriptor !== undefined) {
            fs.closeSync(descriptor);
        }

        try {
            fs.unlinkSync(temporary);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }
    }

    return {
        allowed: true,
        used: used + 1,
        total: state.total,
    };
}

function enforceSandboxLimit(req, res, next) {
    const subscription = req.verifiedSubscription;

    // Existing Production subscriptions have no new request cap.
    if (subscription.environment !== Environment.SANDBOX) {
        return next();
    }

    let logged = false;

    const log = () => {
        if (logged) return;
        logged = true;

        console.info(JSON.stringify({
            timestamp: new Date().toISOString(),
            environment: subscription.environment,
            productId: subscription.productId,
            outcome: res.locals.proxyOutcome ||
                (
                    res.writableFinished
                        ? `http_${res.statusCode}`
                        : 'connection_closed'
                ),
            dailyRequestsUsed: req.sandboxUsage?.used ?? null,
            sandboxRequestsTotal: req.sandboxUsage?.total ?? null,
        }));
    };

    // Exactly one outcome log per authorized Sandbox request.
    res.once('finish', log);
    res.once('close', log);

    try {
        req.sandboxUsage = sandboxUsage(subscription.uid);
    } catch {
        return reject(
            res,
            503,
            'sandbox_usage_storage_unavailable'
        );
    }

    if (!req.sandboxUsage.allowed) {
        const now = new Date();
        const tomorrow = Date.UTC(
            now.getUTCFullYear(),
            now.getUTCMonth(),
            now.getUTCDate() + 1
        );

        res.set(
            'Retry-After',
            String(Math.ceil((tomorrow - now.getTime()) / 1000))
        );

        return reject(res, 429, 'sandbox_daily_limit_reached');
    }

    return next();
}

// Liveness only. This does not declare credentials configured.
app.get('/health', (_req, res) => {
    res.json({ ok: true });
});

app.post(
    '/v1/messages',
    authorize,
    enforceSandboxLimit,
    express.json({ limit: '10mb' }),
    async (req, res) => {
        const apiKey = process.env.ANTHROPIC_API_KEY;

        if (!apiKey || !apiKey.trim()) {
            return reject(res, 503, 'ai_service_unavailable');
        }

        try {
            const upstream = await fetch(
                'https://api.anthropic.com/v1/messages',
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-api-key': apiKey,
                        'anthropic-version': '2023-06-01',
                    },
                    body: JSON.stringify(req.body),
                    signal: AbortSignal.timeout(240000),
                }
            );

            const text = await upstream.text();
            res.locals.proxyOutcome =
                `anthropic_http_${upstream.status}`;

            return res.status(upstream.status)
                .set('Content-Type', 'application/json')
                .send(text);
        } catch {
            console.error('Anthropic request failed');
            return reject(res, 502, 'ai_upstream_unavailable');
        }
    }
);

const port = Number(process.env.PORT || 8080);

app.listen(port, '0.0.0.0', () => {
    console.log(`WASP authenticated proxy listening on port ${port}`);
});
