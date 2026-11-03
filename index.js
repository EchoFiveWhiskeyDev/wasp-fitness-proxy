'use strict';

const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { initializeApp, cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const {
    AppStoreServerAPIClient,
    SignedDataVerifier,
    Environment,
    Status,
} = require('@apple/app-store-server-library');

const app = express();
app.disable('x-powered-by');

const FIREBASE_PROJECT_ID = 'wasp-fitness';
const BUNDLE_ID = 'EchoFiveWhiskey.WASP-Fitness';
const APP_APPLE_ID = 6814244360;

// Sandbox only. Never deploy this branch to the production service.
// No automatic fallback to another Apple environment.
const APPLE_ENVIRONMENT = Environment.SANDBOX;

const PRODUCT_IDS = new Set([
    'WASP_Elite_Monthly',
    'WASP_Elite_Yearly',
    'com.echofivewhiskey.wasp.pro.monthly',
    'com.echofivewhiskey.wasp.pro.yearly',
]);

let firebaseAuth;
let appleServices;

function requiredEnv(name) {
    const value = process.env[name];

    if (!value || !value.trim()) {
        throw new Error(`Missing ${name}`);
    }

    return value;
}

function getFirebaseAuth() {
    if (process.env.FIREBASE_AUTH_EMULATOR_HOST) {
        throw new Error('Firebase emulator is forbidden on this proxy');
    }

    if (!firebaseAuth) {
        const credentials = JSON.parse(
            requiredEnv('FIREBASE_SERVICE_ACCOUNT_JSON')
        );

        if (credentials.project_id !== FIREBASE_PROJECT_ID) {
            throw new Error('Wrong Firebase project');
        }

        const firebaseApp = initializeApp({
            credential: cert(credentials),
            projectId: FIREBASE_PROJECT_ID,
        });

        firebaseAuth = getAuth(firebaseApp);
    }

    return firebaseAuth;
}

function getAppleServices() {
    if (!appleServices) {
        const root = fs.readFileSync(
            path.join(__dirname, 'AppleRootCA-G3.cer')
        );

        const verifier = new SignedDataVerifier(
            [root],
            true,
            APPLE_ENVIRONMENT,
            BUNDLE_ID,
            APP_APPLE_ID
        );

        const client = new AppStoreServerAPIClient(
            requiredEnv('APPLE_PRIVATE_KEY').replace(/\\n/g, '\n'),
            requiredEnv('APPLE_KEY_ID').trim(),
            requiredEnv('APPLE_ISSUER_ID').trim(),
            BUNDLE_ID,
            APPLE_ENVIRONMENT
        );

        appleServices = { verifier, client };
    }

    return appleServices;
}

function accountTokenForUID(uid) {
    const bytes = createHash('sha256')
        .update(`wasp-fitness:app-account:v1:${uid}`, 'utf8')
        .digest()
        .subarray(0, 16);

    // Match the iPhone app's UUIDv8 derivation exactly.
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

function matchesActiveAccount(transaction, expectedToken) {
    return (
        transaction.bundleId === BUNDLE_ID &&
        transaction.environment === APPLE_ENVIRONMENT &&
        transaction.type === 'Auto-Renewable Subscription' &&
        PRODUCT_IDS.has(transaction.productId) &&
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
        // Check token validity, revoked sessions, and disabled users.
        identity = await auth.verifyIdToken(bearer[1], true);

        if (!identity.uid) {
            throw new Error('Missing UID');
        }
    } catch {
        return reject(res, 401, 'invalid_firebase_token');
    }

    // Only explicitly approved Firebase accounts may use this service.
    // Set SANDBOX_FIREBASE_UIDS to comma-separated Firebase UIDs.
    // An empty list blocks every caller.
    const sandboxUIDs = new Set(
        (process.env.SANDBOX_FIREBASE_UIDS || '')
            .split(',')
            .map(uid => uid.trim())
            .filter(Boolean)
    );

    if (sandboxUIDs.size === 0) {
        return reject(res, 503, 'sandbox_test_accounts_not_configured');
    }

    if (!sandboxUIDs.has(identity.uid)) {
        // Temporary diagnostics. Never log raw UIDs or credentials.
        const fingerprint = value =>
            createHash('sha256')
                .update(value, 'utf8')
                .digest('hex')
                .slice(0, 12);

        console.warn('Sandbox allowlist mismatch', {
            authenticatedAccount: fingerprint(identity.uid),
            approvedAccountCount: sandboxUIDs.size,
            approvedAccounts: [...sandboxUIDs].map(fingerprint),
        });

        return reject(res, 403, 'sandbox_account_not_allowed');
    }

    let apple;

    try {
        apple = getAppleServices();
    } catch {
        console.error('Apple verification configuration unavailable');
        return reject(res, 503, 'subscription_verification_unavailable');
    }

    const expectedToken = accountTokenForUID(identity.uid);
    let supplied;

    try {
        supplied = await apple.verifier.verifyAndDecodeTransaction(jws);
    } catch {
        return reject(res, 403, 'invalid_subscription_jws');
    }

    if (!matchesActiveAccount(supplied, expectedToken)) {
        return reject(res, 403, 'subscription_not_active_or_not_owned');
    }

    // A signed transaction is a snapshot. Check current status with
    // Apple to catch later refunds and revocations.
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
                    matchesActiveAccount(latest, expectedToken)
                ) {
                    return next();
                }
            }
        }
    } catch {
        return reject(res, 503, 'subscription_status_unverifiable');
    }

    return reject(res, 403, 'active_owned_subscription_required');
}

// Liveness only. This does not declare authentication configured.
app.get('/health', (_req, res) => {
    res.json({ ok: true });
});

app.post(
    '/v1/messages',
    authorize,
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
