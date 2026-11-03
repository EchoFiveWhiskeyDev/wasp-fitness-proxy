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
// There is no automatic fallback to another Apple environment.
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

async function authorize(req, res,
