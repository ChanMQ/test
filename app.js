// --- FRAMEBUSTING & SECURITY INIT ---
try {
    const antiClickjack = document.getElementById('antiClickjack');
    if (antiClickjack) antiClickjack.remove();
    if (self !== top) {
        try { top.location = self.location; } catch (e) {}
    }
} catch (e) {
    console.warn('Framebusting init failed', e);
}

function finishBoot(preloader) {
    try {
        if (preloader) preloader.classList.add('hidden');
        document.body.classList.remove('loading');
    } catch (e) {}
}

window.addEventListener('error', () => finishBoot(document.getElementById('preloader')));
window.addEventListener('unhandledrejection', () => finishBoot(document.getElementById('preloader')));

// --- SECURE SESSION MODULE (INDEXEDDB + WEBCRYPTO) ---

const SecureSession = (function() {
    const DB_NAME = 'E2ENetworkDB';
    const DB_VERSION = 3;
    const STORE_NAME = 'secure_session';
    const FALLBACK_KEY = 'e2e_secure_session_fallback';

    function storageAvailable() {
        return typeof indexedDB !== 'undefined' && typeof crypto !== 'undefined' && !!crypto.subtle;
    }

    function saveFallback(sessionData) {
        try {
            localStorage.setItem(FALLBACK_KEY, JSON.stringify(sessionData));
            return true;
        } catch (e) {
            console.warn('Fallback session save failed', e);
            return false;
        }
    }

    function loadFallback() {
        try {
            const raw = localStorage.getItem(FALLBACK_KEY);
            if (!raw) return null;
            const payload = JSON.parse(raw);
            if (!payload || typeof payload !== 'object') return null;
            return {
                baseUrl: payload.baseUrl,
                userId: payload.userId,
                token: payload.token,
                refreshToken: payload.refreshToken || null
            };
        } catch (e) {
            localStorage.removeItem(FALLBACK_KEY);
            return null;
        }
    }

    function clearFallback() {
        try { localStorage.removeItem(FALLBACK_KEY); } catch (e) {}
    }

    function openDB() {
        return new Promise((resolve, reject) => {
            if (!storageAvailable()) {
                reject(new Error('Secure storage unavailable'));
                return;
            }
            const req = indexedDB.open(DB_NAME, DB_VERSION);
            req.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    db.createObjectStore(STORE_NAME);
                }
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    }

    async function getOrGenerateKey(db) {
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readonly');
            const store = tx.objectStore(STORE_NAME);
            const req = store.get('crypto_key');
            req.onsuccess = async () => {
                if (req.result) {
                    resolve(req.result);
                } else {
                    try {
                        const key = await crypto.subtle.generateKey(
                            { name: 'AES-GCM', length: 256 },
                            false,
                            ['encrypt', 'decrypt']
                        );

                        const writeTx = db.transaction(STORE_NAME, 'readwrite');
                        const writeStore = writeTx.objectStore(STORE_NAME);
                        writeStore.put(key, 'crypto_key').onsuccess = () => resolve(key);
                        writeStore.onerror = () => reject(writeTx.error);
                    } catch (e) {
                        reject(e);
                    }
                }
            };
            req.onerror = () => reject(tx.error);
        });
    }

    async function save(sessionOrBaseUrl, userId, token, refreshToken = null) {
        const sessionData = typeof sessionOrBaseUrl === 'object'
            ? sessionOrBaseUrl
            : { baseUrl: sessionOrBaseUrl, userId, token, refreshToken };

        if (!storageAvailable()) {
            saveFallback(sessionData);
            return;
        }

        try {
            const db = await openDB();
            const key = await getOrGenerateKey(db);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encodedPayload = new TextEncoder().encode(JSON.stringify(sessionData));

            const ciphertext = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                key,
                encodedPayload
            );

            await new Promise((resolve, reject) => {
                const tx = db.transaction(STORE_NAME, 'readwrite');
                const store = tx.objectStore(STORE_NAME);
                store.put({ iv, ciphertext }, 'session_data');
                tx.oncomplete = () => resolve();
                tx.onerror = () => reject(tx.error);
            });
            clearFallback();
        } catch (e) {
            console.warn('Session save failed, using fallback storage', e);
            saveFallback(sessionData);
        }
    }

    async function load() {
        if (!storageAvailable()) {
            return loadFallback();
        }

        try {
            const db = await openDB();
            const loaded = await new Promise((resolve, reject) => {
                const tx = db.transaction(STORE_NAME, 'readonly');
                const store = tx.objectStore(STORE_NAME);
                const keyReq = store.get('crypto_key');
                const dataReq = store.get('session_data');

                tx.oncomplete = async () => {
                    const key = keyReq.result;
                    const data = dataReq.result;

                    if (!key || !data) {
                        resolve(null);
                        return;
                    }

                    try {
                        const decrypted = await crypto.subtle.decrypt(
                            { name: 'AES-GCM', iv: data.iv },
                            key,
                            data.ciphertext
                        );
                        const payload = JSON.parse(new TextDecoder().decode(decrypted));
                        resolve({
                            baseUrl: payload.baseUrl,
                            userId: payload.userId,
                            token: payload.token,
                            refreshToken: payload.refreshToken || null
                        });
                    } catch (e) {
                        console.warn('Decryption failed. Clearing corrupted data.');
                        await clear();
                        resolve(null);
                    }
                };
                tx.onerror = () => reject(tx.error);
            });
            return loaded || loadFallback();
        } catch (e) {
            console.warn('Secure session load failed, using fallback storage', e);
            return loadFallback();
        }
    }

    async function clear() {
        try {
            if (storageAvailable()) {
                const db = await openDB();
                await new Promise((resolve) => {
                    const tx = db.transaction(STORE_NAME, 'readwrite');
                    const store = tx.objectStore(STORE_NAME);
                    store.delete('session_data');
                    store.delete('crypto_key');
                    tx.oncomplete = () => resolve();
                });
            }
        } catch(e) {}

        clearFallback();
        localStorage.removeItem('matrix_pending_hs');
    }

    return { save, load, clear };
})();;


// --- SAFE DOM SVG FACTORY ---

// --- SAFE DOM SVG FACTORY ---
const svgRegistry = {
    login: [{ tag: 'path', attrs: { d: 'M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4' } }, { tag: 'polyline', attrs: { points: '10 17 15 12 10 7' } }, { tag: 'line', attrs: { x1: '15', y1: '12', x2: '3', y2: '12' } }],
    register: [{ tag: 'path', attrs: { d: 'M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2' } }, { tag: 'circle', attrs: { cx: '8.5', cy: '7', r: '4' } }, { tag: 'line', attrs: { x1: '20', y1: '8', x2: '20', y2: '14' } }, { tag: 'line', attrs: { x1: '23', y1: '11', x2: '17', y2: '11' } }],
    eyeOpen: [{ tag: 'path', attrs: { d: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z' } }, { tag: 'circle', attrs: { cx: '12', cy: '12', r: '3' } }],
    eyeClosed: [{ tag: 'path', attrs: { d: 'M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24M1 1l22 22' } }],
    check: [{ tag: 'polyline', attrs: { points: '20 6 9 17 4 12' } }],
    success: [{ tag: 'path', attrs: { d: 'M22 11.08V12a10 10 0 1 1-5.93-9.14' } }, { tag: 'polyline', attrs: { points: '22 4 12 14.01 9 11.01' } }],
    info: [{ tag: 'circle', attrs: { cx: '12', cy: '12', r: '10' } }, { tag: 'line', attrs: { x1: '12', y1: '16', x2: '12', y2: '12' } }, { tag: 'line', attrs: { x1: '12', y1: '8', x2: '12.01', y2: '8' } }],
    error: [{ tag: 'circle', attrs: { cx: '12', cy: '12', r: '10' } }, { tag: 'line', attrs: { x1: '12', y1: '8', x2: '12', y2: '12' } }, { tag: 'line', attrs: { x1: '12', y1: '16', x2: '12.01', y2: '16' } }]
};

function createSvgIcon(name, props = {}) {
    const data = svgRegistry[name];
    if (!data) return document.createElement('span');

    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true"); // ARIA скрытие для всех создаваемых SVG-иконок

    Object.entries(props).forEach(([k, v]) => svg.setAttribute(k, v));

    data.forEach(el => {
        const child = document.createElementNS("http://www.w3.org/2000/svg", el.tag);
        Object.entries(el.attrs).forEach(([k, v]) => child.setAttribute(k, v));
        svg.appendChild(child);
    });
    return svg;
}


// --- MATRIX CLIENT LOGIC & STATE ---
const APP_DEVICE_NAME = 'e2e.network Web';
const DEVICE_ID_KEY = 'e2e_matrix_device_id';
const PENDING_HS_KEY = 'matrix_pending_hs';

let syncAbortController = null;
let syncNextBatch = null;
let syncRetryCount = 0;
let syncRetryTimeout = null;
let currentDropdownIndex = -1;

let activeStep = 'stepWelcome';
let currentFlow = 'login';
let currentBaseUrl = '';
let serverSupportsSSO = false;
let serverSupportsPassword = true;

let authAbortController = null;

class MatrixError extends Error {
    constructor(message, { errcode = '', status = 0, softLogout = false, data = null } = {}) {
        super(message);
        this.name = 'MatrixError';
        this.errcode = errcode;
        this.status = status;
        this.softLogout = softLogout;
        this.data = data;
    }
}

function getOrCreateDeviceId() {
    let existing = localStorage.getItem(DEVICE_ID_KEY);
    if (existing) return existing;
    const randomPart = (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2)).replace(/-/g, '').slice(0, 16).toUpperCase();
    existing = `E2EWEB${randomPart}`.slice(0, 24);
    localStorage.setItem(DEVICE_ID_KEY, existing);
    return existing;
}

function getDisplayServerName(baseUrl) {
    try {
        return new URL(baseUrl).host;
    } catch (e) {
        return String(baseUrl || '').replace(/^https?:\/\//i, '').replace(/\/$/, '');
    }
}

function normalizeHomeserverInput(rawValue) {
    const value = String(rawValue || '').trim();
    if (!value) return '';

    if (/^https?:\/\//i.test(value)) {
        try {
            return new URL(value).origin;
        } catch (e) {
            return value.replace(/\/$/, '');
        }
    }

    return value.replace(/^https?:\/\//i, '').split('/')[0].replace(/\/$/, '');
}

function parseMatrixIdentifier(value) {
    const trimmed = String(value || '').trim();
    const match = trimmed.match(/^@[^:\s]+:([^\s]+)$/);
    if (!match) return null;
    return { mxid: trimmed, server: match[1] };
}

function abortAuthRequests() {
    if (authAbortController) {
        authAbortController.abort();
        authAbortController = null;
    }
}

function resetAllSpinners() {
    setButtonLoading('btnServerNext', false);
    setButtonLoading('btnAuthSubmit', false);
    setButtonLoading('btnResetSubmit', false);
    setButtonLoading('ssoBtn', false);
}

function getNewAuthSignal() {
    abortAuthRequests();
    authAbortController = new AbortController();
    return authAbortController.signal;
}


async function getBaseUrl(hsDomain, signal) {
    const normalized = normalizeHomeserverInput(hsDomain);
    if (!normalized) throw new Error('Invalid homeserver');

    if (/^https?:\/\//i.test(normalized)) {
        return normalized.replace(/\/$/, '');
    }

    const domain = normalized;
    try {
        const res = await fetch(`https://${domain}/.well-known/matrix/client`, { signal });
        if (res.ok) {
            const data = await res.json();
            if (data?.['m.homeserver']?.base_url) {
                return String(data['m.homeserver'].base_url).replace(/\/$/, '');
            }
        }
    } catch (e) {
        if (e.name === 'AbortError') throw e;
    }
    return `https://${domain}`;
}

async function getJsonOrEmpty(res) {
    try {
        return await res.json();
    } catch (e) {
        return {};
    }
}

async function throwMatrixError(res, fallbackMessage) {
    const data = await getJsonOrEmpty(res);
    throw new MatrixError(data.error || fallbackMessage, {
        errcode: data.errcode || '',
        status: res.status,
        softLogout: !!data.soft_logout,
        data
    });
}

async function validateHomeserver(baseUrl, signal) {
    const res = await fetch(`${baseUrl}/_matrix/client/versions`, { signal });
    if (!res.ok) {
        await throwMatrixError(res, 'Homeserver validation failed');
    }
    return getJsonOrEmpty(res);
}

async function verifyToken(baseUrl, token) {
    try {
        const res = await fetch(`${baseUrl}/_matrix/client/v3/account/whoami`, {
            headers: { Authorization: `Bearer ${token}` }
        });
        if (res.ok) return true;
        const data = await getJsonOrEmpty(res);
        if (data.errcode === 'M_UNKNOWN_TOKEN') return false;
        return false;
    } catch (e) {
        return false;
    }
}

async function refreshAccessToken(session, signal) {
    if (!session?.refreshToken) throw new MatrixError('Missing refresh token', { errcode: 'M_UNKNOWN_TOKEN' });

    const res = await fetch(`${session.baseUrl}/_matrix/client/v3/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: session.refreshToken }),
        signal
    });

    if (!res.ok) {
        await throwMatrixError(res, 'Token refresh failed');
    }

    const data = await getJsonOrEmpty(res);
    const updatedSession = {
        baseUrl: session.baseUrl,
        userId: session.userId,
        token: data.access_token,
        refreshToken: data.refresh_token || session.refreshToken
    };
    await SecureSession.save(updatedSession);
    return updatedSession;
}

async function ensureSessionReady(session) {
    if (!session) return null;
    if (await verifyToken(session.baseUrl, session.token)) return session;

    if (session.refreshToken) {
        try {
            return await refreshAccessToken(session);
        } catch (err) {
            if (err.softLogout) {
                showGlobalError('errSessionExpired', 'info');
            }
        }
    }

    return null;
}

function buildLoginRequestBody(type, extra = {}) {
    return {
        type,
        device_id: getOrCreateDeviceId(),
        initial_device_display_name: APP_DEVICE_NAME,
        refresh_token: true,
        ...extra
    };
}

async function matrixLogin(baseUrl, username, password, signal) {
    const res = await fetch(`${baseUrl}/_matrix/client/v3/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(buildLoginRequestBody('m.login.password', {
            identifier: { type: 'm.id.user', user: username },
            password
        })),
        signal
    });

    if (!res.ok) {
        await throwMatrixError(res, 'Login failed');
    }
    return getJsonOrEmpty(res);
}

async function matrixTokenLogin(baseUrl, loginToken, signal) {
    const res = await fetch(`${baseUrl}/_matrix/client/v3/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(buildLoginRequestBody('m.login.token', { token: loginToken })),
        signal
    });

    if (!res.ok) {
        await throwMatrixError(res, 'SSO token login failed');
    }
    return getJsonOrEmpty(res);
}

async function matrixRegister(baseUrl, username, password, signal) {
    const requestBody = {
        username,
        password,
        inhibit_login: false,
        device_id: getOrCreateDeviceId(),
        initial_device_display_name: APP_DEVICE_NAME,
        refresh_token: true
    };

    let res = await fetch(`${baseUrl}/_matrix/client/v3/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
        signal
    });

    if (res.ok) return getJsonOrEmpty(res);

    if (res.status === 401) {
        const data = await getJsonOrEmpty(res);
        const flows = Array.isArray(data.flows) ? data.flows : [];
        const supportsDummy = flows.some(flow => Array.isArray(flow.stages) && flow.stages.includes('m.login.dummy'));
        const supportsSSOOnly = flows.length > 0 && flows.every(flow => Array.isArray(flow.stages) && flow.stages.some(stage => stage === 'm.login.sso' || stage === 'm.oauth'));

        if (supportsSSOOnly && !supportsDummy) {
            throw new MatrixError('This server only supports SSO for registration.', { errcode: 'UIAA_SSO_ONLY', status: 401, data });
        }

        if (!supportsDummy) {
            throw new MatrixError('Additional verification is required by this homeserver.', { errcode: 'UIAA_UNSUPPORTED', status: 401, data });
        }

        const secondRes = await fetch(`${baseUrl}/_matrix/client/v3/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...requestBody,
                auth: { type: 'm.login.dummy', session: data.session }
            }),
            signal
        });

        if (!secondRes.ok) {
            await throwMatrixError(secondRes, 'Registration failed');
        }
        return getJsonOrEmpty(secondRes);
    }

    await throwMatrixError(res, 'Registration failed');
}

async function requestPasswordReset(baseUrl, email, signal) {
    const body = {
        client_secret: (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2)),
        email,
        send_attempt: Date.now()
    };

    const res = await fetch(`${baseUrl}/_matrix/client/v3/account/password/email/requestToken`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal
    });

    if (!res.ok) {
        await throwMatrixError(res, 'Password reset is not available');
    }

    return getJsonOrEmpty(res);
}

function setSyncStatus(kind, payload = {}) {
    const syncText = document.getElementById('syncText');
    if (!syncText) return;

    if (kind === 'syncing') {
        syncText.textContent = t('syncingStatus', 'Syncing with Matrix...');
        return;
    }

    if (kind === 'synced') {
        const template = t('syncedStatus', 'Connected to Matrix. {batch}');
        syncText.textContent = template.replace('{batch}', payload.batch || '');
        return;
    }

    if (kind === 'retrying') {
        const template = t('retryingStatus', 'Connection error. Retrying in {seconds}s...');
        syncText.textContent = template.replace('{seconds}', String(payload.seconds ?? ''));
    }
}

function clearSyncState({ resetNextBatch = false } = {}) {
    if (syncAbortController) {
        syncAbortController.abort();
        syncAbortController = null;
    }
    if (syncRetryTimeout) {
        clearTimeout(syncRetryTimeout);
        syncRetryTimeout = null;
    }
    syncRetryCount = 0;
    if (resetNextBatch) syncNextBatch = null;
}

async function handleSyncTokenFailure(baseUrl) {
    const session = await SecureSession.load();
    if (!session) {
        await performLogout({ remote: false, messageKey: 'errSessionExpired', toastType: 'info' });
        return null;
    }

    if (session.refreshToken) {
        try {
            const refreshed = await refreshAccessToken(session);
            return refreshed.token;
        } catch (err) {
            if (err.softLogout) {
                await performLogout({ remote: false, messageKey: 'errSessionExpired', toastType: 'info' });
                return null;
            }
        }
    }

    await performLogout({ remote: false, messageKey: 'errSessionExpired', toastType: 'info' });
    return null;
}

async function startMatrixSync(baseUrl, accessToken) {
    if (!accessToken || !document.getElementById('appContainer')?.classList.contains('active')) return;

    setSyncStatus('syncing');

    try {
        const syncUrl = new URL(`${baseUrl}/_matrix/client/v3/sync`);
        syncUrl.searchParams.append('timeout', '30000');
        if (syncNextBatch) syncUrl.searchParams.append('since', syncNextBatch);
        syncAbortController = new AbortController();
        const res = await fetch(syncUrl, {
            headers: { Authorization: `Bearer ${accessToken}` },
            signal: syncAbortController.signal
        });

        if (res.ok) {
            syncRetryCount = 0;
            const data = await getJsonOrEmpty(res);
            syncNextBatch = data.next_batch;
            setSyncStatus('synced', { batch: syncNextBatch ? `${syncNextBatch.substring(0, 8)}...` : '' });
            startMatrixSync(baseUrl, accessToken);
            return;
        }

        const errorData = await getJsonOrEmpty(res);
        if (res.status === 401 && errorData.errcode === 'M_UNKNOWN_TOKEN') {
            const refreshedToken = await handleSyncTokenFailure(baseUrl);
            if (refreshedToken) {
                startMatrixSync(baseUrl, refreshedToken);
            }
            return;
        }

        handleSyncRetry(baseUrl, accessToken);
    } catch (e) {
        if (e.name !== 'AbortError') {
            handleSyncRetry(baseUrl, accessToken);
        }
    }
}

function handleSyncRetry(baseUrl, accessToken) {
    const delay = Math.min(2000 * Math.pow(2, syncRetryCount), 60000);
    syncRetryCount += 1;
    setSyncStatus('retrying', { seconds: Math.ceil(delay / 1000) });
    if (syncRetryTimeout) clearTimeout(syncRetryTimeout);
    syncRetryTimeout = setTimeout(() => {
        syncRetryTimeout = null;
        startMatrixSync(baseUrl, accessToken);
    }, delay);
}

function rememberHomeserver(baseUrl) {
    const hsInput = document.getElementById('homeserver');
    const resetHsInput = document.getElementById('resetHomeserver');
    const display = getDisplayServerName(baseUrl);
    if (hsInput && display) hsInput.value = display;
    if (resetHsInput && display) resetHsInput.value = display;
}

function showAppScreen(baseUrl, accessToken) {
    currentBaseUrl = baseUrl;
    rememberHomeserver(baseUrl);
    document.getElementById('authContainer').style.display = 'none';
    document.getElementById('appContainer').classList.add('active');
    startMatrixSync(baseUrl, accessToken);
}

async function performLogout({ remote = true, messageKey = '', toastType = 'info' } = {}) {
    clearSyncState({ resetNextBatch: true });
    abortAuthRequests();

    const session = await SecureSession.load();
    if (remote && session?.token) {
        try {
            await fetch(`${session.baseUrl}/_matrix/client/v3/logout`, {
                method: 'POST',
                headers: { Authorization: `Bearer ${session.token}` }
            });
        } catch (e) {}
    }

    await SecureSession.clear();

    document.getElementById('appContainer').classList.remove('active');
    document.getElementById('authContainer').style.display = 'flex';
    document.getElementById('password').value = '';
    document.getElementById('confirmPassword').value = '';
    setSyncStatus('syncing');
    configureCredentialsStep();
    goToStep('stepWelcome');

    if (messageKey) {
        showGlobalError(messageKey, toastType);
    }
}

function setButtonLoading(btnId, isLoading) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    if (isLoading) {
        btn.classList.add('is-loading');
        btn.disabled = true;
    } else {
        btn.classList.remove('is-loading');
        btn.disabled = false;
    }
}

// --- UI WIZARD & LANG LOGIC ---
const languages = window.authLanguages || [];
const i18n = window.authI18n || {};
let currentLangCode = 'en';

function detectLanguage() {
    const availableCodes = languages.map(l => l.code);
    const availableCodesLower = new Map(languages.map(l => [l.code.toLowerCase(), l.code]));
    const savedLang = localStorage.getItem('e2e_preferred_lang');
    if (savedLang && availableCodes.includes(savedLang)) return savedLang;
    if (navigator.language) {
        const browserLang = navigator.language.toLowerCase();
        if (availableCodesLower.has(browserLang)) return availableCodesLower.get(browserLang);
        const shortLang = browserLang.split('-')[0];
        if (availableCodesLower.has(shortLang)) return availableCodesLower.get(shortLang);
    }
    return 'en';
}

function getDict() { return i18n[currentLangCode] || i18n['en'] || {}; }
function t(key, fallback = '') { const current = i18n[currentLangCode] || {}; const en = i18n['en'] || {}; return current[key] || en[key] || fallback || key; }

let cachedLangItems = [];

function renderLanguagesInitial() {
    const langListEl = document.getElementById('langList');
    if (!langListEl) return;

    while(langListEl.firstChild) langListEl.removeChild(langListEl.firstChild);
    cachedLangItems = [];

    languages.forEach(lang => {
        const div = document.createElement('div');
        div.className = `lang-item ${lang.code === currentLangCode ? 'selected' : ''}`;
        div.dataset.search = lang.name.toLowerCase();

        const textSpan = document.createElement('span');
        textSpan.textContent = lang.name;
        div.appendChild(textSpan);

        if (lang.code === currentLangCode) {
            div.appendChild(createSvgIcon('check', { width: "20", height: "20", "stroke-width": "2.5" }));
        }

        div.addEventListener('click', () => selectLanguage(lang.code, lang.name));
        langListEl.appendChild(div);
        cachedLangItems.push(div);
    });
}

function filterLanguages() {
    const langSearchInput = document.getElementById('langSearch');
    const langListEl = document.getElementById('langList');
    const clearBtn = document.getElementById('btnLangClear');
    if(!langSearchInput || !langListEl) return;

    const filterText = langSearchInput.value.toLowerCase();
    let visibleCount = 0;

    if (clearBtn) {
        if (filterText.length > 0) clearBtn.classList.add('active');
        else clearBtn.classList.remove('active');
    }

    requestAnimationFrame(() => {
        cachedLangItems.forEach(div => {
            if (div.dataset.search.includes(filterText)) { div.style.display = 'flex'; visibleCount++; }
            else { div.style.display = 'none'; }
        });

        let emptyEl = document.getElementById('langEmptyState');
        if (visibleCount === 0) {
            if (!emptyEl) {
                emptyEl = document.createElement('div');
                emptyEl.id = 'langEmptyState';
                emptyEl.className = 'lang-empty';
                emptyEl.style.flexDirection = 'column';

                const logoSvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
                logoSvg.setAttribute("viewBox", "0 0 200 200");
                logoSvg.setAttribute("width", "64");
                logoSvg.setAttribute("height", "64");
                logoSvg.style.marginBottom = "12px";

                const paths = [
                    "M 90 40 C 50 15, 20 60, 30 100 C 35 140, 60 180, 95 160 C 115 148, 105 125, 88 120 C 70 112, 70 88, 88 80 C 105 75, 115 52, 90 40 Z",
                    "M 118 48 C 128 52, 142 52, 152 48 C 148 60, 148 76, 152 88 C 142 84, 128 84, 118 88 C 122 76, 122 60, 118 48 Z",
                    "M 118 112 C 128 116, 142 116, 152 112 C 148 124, 148 140, 152 152 C 142 148, 128 148, 118 152 C 122 140, 122 124, 118 112 Z"
                ];

                paths.forEach(d => {
                    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
                    path.setAttribute("fill", "var(--text-muted)");
                    path.setAttribute("d", d);
                    logoSvg.appendChild(path);
                });

                const textSpan = document.createElement('span');
                textSpan.id = 'langEmptyText';
                textSpan.textContent = getDict().langEmpty || 'No languages found';

                emptyEl.appendChild(logoSvg);
                emptyEl.appendChild(textSpan);
                langListEl.appendChild(emptyEl);
            } else {
                emptyEl.style.display = 'flex';
                const textSpan = document.getElementById('langEmptyText');
                if (textSpan) textSpan.textContent = getDict().langEmpty || 'No languages found';
            }
        } else if (emptyEl) {
            emptyEl.style.display = 'none';
        }
    });
}

function scrollToSelectedLanguage() {
    const langListEl = document.getElementById('langList');
    if(!langListEl) return;
    const selectedEl = langListEl.querySelector('.lang-item.selected');
    if (!selectedEl) return;
    langListEl.scrollTop = Math.max(0, selectedEl.offsetTop - (langListEl.clientHeight / 2) + (selectedEl.offsetHeight / 2));
}

function openLangModal() {
    const langModalOverlay = document.getElementById('langModalOverlay');
    const langSearchInput = document.getElementById('langSearch');
    const langListEl = document.getElementById('langList');
    const clearBtn = document.getElementById('btnLangClear');

    if (langModalOverlay.classList.contains('active')) { closeLangModalBtn(); return; }

    if(langSearchInput) langSearchInput.value = '';
    if(clearBtn) clearBtn.classList.remove('active');

    renderLanguagesInitial();
    if(langListEl) langListEl.scrollTop = 0;

    langModalOverlay.classList.add('active');
    requestAnimationFrame(() => {
        scrollToSelectedLanguage();
        if(langSearchInput) langSearchInput.focus();
    });
}

function closeLangModalBtn() {
    const langModalOverlay = document.getElementById('langModalOverlay');
    if(langModalOverlay) langModalOverlay.classList.remove('active');
}

function selectLanguage(code, name) {
    const currentLangBtnText = document.getElementById('currentLangBtnText');
    currentLangCode = code;
    if(currentLangBtnText) currentLangBtnText.textContent = name;
    localStorage.setItem('e2e_preferred_lang', code);
    closeLangModalBtn();
    updateUI();
    hideGlobalError();
}

function safeSetText(id, text) {
    const el = document.getElementById(id);
    if(el && text) el.textContent = text;
}


function updateUI() {
    const activeLangObj = languages.find(l => l.code === currentLangCode) || languages.find(l => l.code === 'en');

    document.documentElement.lang = currentLangCode;
    document.documentElement.dir = ['ar', 'he', 'fa'].includes(currentLangCode) ? 'rtl' : 'ltr';

    if (activeLangObj) safeSetText('currentLangBtnText', activeLangObj.name);

    const searchInput = document.getElementById('langSearch');
    if (searchInput) searchInput.placeholder = t('searchPlace', 'Search...');

    safeSetText('btnLangCloseText', t('btnClose', 'Close'));
    safeSetText('txtWelcomeTitle', t('welcomeTitle', 'e2e.network'));
    safeSetText('txtWelcomeSub', t('welcomeSub', 'Decentralized secure communication.'));
    safeSetText('btnWelcomeLogin', t('btnWelcomeLogin', 'LOG IN'));
    safeSetText('btnWelcomeReg', t('btnWelcomeReg', 'CREATE ACCOUNT'));
    safeSetText('txtServerTitle', t('titleServer', 'Choose Server'));
    safeSetText('txtServerSub', currentFlow === 'login' ? t('subServerLogin', 'Where is your account hosted?') : t('subServerReg', 'Where do you want to create an account?'));
    safeSetText('lblHomeserver', t('lblHomeserver', 'Homeserver (e.g. matrix.org)'));
    safeSetText('txtPopularServers', t('txtPopularServers', 'Popular Servers'));
    safeSetText('txtBtnNext', t('btnNext', 'CONTINUE'));
    safeSetText('txtAuthTitle', currentFlow === 'login' ? t('titleAuthLogin', 'Log In') : t('titleAuthReg', 'Create Account'));
    safeSetText('txtAuthSub', t('subAuth', 'Enter your details.'));
    safeSetText('lblUsername', currentFlow === 'login' ? t('lblUsernameLogin', 'Username or @user:server') : t('lblUsernameReg', 'Username'));
    safeSetText('lblEmail', t('lblEmail', 'Email'));
    safeSetText('lblPassword', currentFlow === 'login' ? t('lblPasswordLogin', 'Password') : t('lblPasswordReg', 'Create Password'));
    safeSetText('lblConfirm', t('lblConfirm', 'Confirm Password'));
    safeSetText('lnkForgot', t('lnkForgot', 'Forgot Password?'));
    safeSetText('txtBtnAuthSubmit', currentFlow === 'login' ? t('btnAuthLogin', 'LOG IN') : t('btnAuthReg', 'REGISTER'));

    const iconWrap = document.getElementById('primaryIconWrap');
    if (iconWrap) {
        iconWrap.textContent = '';
        iconWrap.appendChild(createSvgIcon(currentFlow === 'login' ? 'login' : 'register', { width: '20', height: '20' }));
    }

    safeSetText('btnSsoText', t('ssoText', 'CONTINUE WITH SSO'));
    safeSetText('ssoDivider', t('ssoOr', 'OR'));
    safeSetText('txtSsoOnlyExpl', t('ssoOnlyExpl', 'This server uses SSO. You will be redirected.'));
    safeSetText('txtResetTitle', t('titleReset', 'Reset Password'));
    safeSetText('txtResetSub', t('subReset', 'Enter server and email.'));
    safeSetText('lblResetHs', t('lblResetHs', t('lblHomeserver', 'Homeserver')));
    safeSetText('lblResetEmail', t('lblEmail', 'Email'));
    safeSetText('txtBtnResetSubmit', t('btnSendReset', 'SEND LINK'));

    const logoutBtnText = document.querySelector('#btnLogout .btn-content span:last-child');
    if (logoutBtnText) logoutBtnText.textContent = t('btnLogout', 'LOGOUT');

    updatePasswordAutocomplete();
    updatePasswordStrength(document.getElementById('password')?.value || '');
    setSyncStatus('syncing');
}

function startFlow(flow) {
    currentFlow = flow;
    updateUI();
    goToStep('stepServer');
}

function goToStep(stepId) {
    hideGlobalError();
    document.querySelectorAll('.input-group.invalid').forEach(el => el.classList.remove('invalid'));

    const currentEl = document.getElementById(activeStep);
    const nextEl = document.getElementById(stepId);

    if(currentEl) currentEl.style.display = 'none';
    if(nextEl) {
        nextEl.style.display = 'flex';
        nextEl.style.animation = 'none';
        void nextEl.offsetWidth;
        nextEl.style.animation = 'fadeUp 0.3s var(--ios-ease) forwards';
    }

    activeStep = stepId;
    if (stepId === 'stepReset') {
        const hsInput = document.getElementById('homeserver');
        const resetHsInput = document.getElementById('resetHomeserver');
        if(hsInput && resetHsInput) resetHsInput.value = hsInput.value.trim();
    }
    setTimeout(refreshAutofillStyles, 50);
}


function clearError(input) {
    const group = input.closest('.input-group');
    if (group) group.classList.remove('invalid');
    input.setAttribute('aria-invalid', 'false');
}

function removeToast(toast) {
    if (!toast.classList.contains('active')) return;
    toast.classList.remove('active');
    setTimeout(() => toast.remove(), 300);
}


function showGlobalError(msgKey, type = 'error') {
    const msg = t(msgKey, msgKey);
    const container = document.getElementById('toastContainer');
    if(!container) return;

    const existingToasts = container.querySelectorAll('.toast-item');
    if (existingToasts.length >= 3) { existingToasts[0].remove(); }

    const toast = document.createElement('div');
    toast.className = `toast-item toast-${type}`;
    toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
    toast.setAttribute('tabindex', '0');

    const iconSpan = document.createElement('span');
    iconSpan.className = 'toast-icon';
    iconSpan.appendChild(createSvgIcon(type === 'success' ? 'success' : type === 'info' ? 'info' : 'error', { width: '18', height: '18', 'stroke-width': '2.5' }));

    const textSpan = document.createElement('span');
    textSpan.className = 'toast-msg';
    textSpan.textContent = msg;

    toast.appendChild(iconSpan);
    toast.appendChild(textSpan);
    container.appendChild(toast);

    requestAnimationFrame(() => {
        requestAnimationFrame(() => {
            toast.classList.add('active');
        });
    });

    let removeTimeout = setTimeout(() => {
        removeToast(toast);
    }, 4000);

    toast.addEventListener('click', () => {
        clearTimeout(removeTimeout);
        removeToast(toast);
    });
}

function hideGlobalError() {
    document.querySelectorAll('.toast-item').forEach(toast => {
        removeToast(toast);
    });
}


function checkField(id, condition, msgKey) {
    const el = document.getElementById(id);
    if(!el) return false;
    const group = el.closest('.input-group');
    const errText = group?.querySelector('.error-text');
    if (!condition) {
        group?.classList.remove('invalid'); void group?.offsetWidth;
        group?.classList.add('invalid');
        el.setAttribute('aria-invalid', 'true');
        if(errText) errText.textContent = t(msgKey, msgKey);
        return false;
    }
    el.setAttribute('aria-invalid', 'false');
    return true;
}


function openDropdown() {
    const hsGroup = document.getElementById('hsGroup');
    const toggleBtn = document.getElementById('btnDropdownToggle');
    if(hsGroup) hsGroup.classList.add('open');
    if(toggleBtn) toggleBtn.setAttribute('aria-expanded', 'true');
}


function closeDropdown(e) {
    if(e) e.stopPropagation();
    const hsGroup = document.getElementById('hsGroup');
    const toggleBtn = document.getElementById('btnDropdownToggle');
    if(hsGroup) hsGroup.classList.remove('open');
    if(toggleBtn) toggleBtn.setAttribute('aria-expanded', 'false');
    currentDropdownIndex = -1;
}


function toggleDropdown(e) {
    e.stopPropagation();
    const hsGroup = document.getElementById('hsGroup');
    const homeserverInput = document.getElementById('homeserver');
    if(!hsGroup) return;

    if (hsGroup.classList.contains('open')) {
        closeDropdown(e);
    } else {
        openDropdown();
        if(homeserverInput) homeserverInput.focus();
    }
}


function updateActiveServerHighlight() {
    const homeserverInput = document.getElementById('homeserver');
    if(!homeserverInput) return;
    const currentVal = homeserverInput.value.trim().toLowerCase();
    document.querySelectorAll('.dropdown-item[data-server]').forEach(item => {
        const isActive = item.getAttribute('data-server').toLowerCase() === currentVal;
        item.classList.toggle('active', isActive);
        item.setAttribute('aria-selected', isActive ? 'true' : 'false');
    });
}

function handleInput(input) {
    abortAuthRequests();
    resetAllSpinners();
    clearError(input);
    openDropdown();
    updateActiveServerHighlight();
}


function selectServer(server) {
    abortAuthRequests();
    resetAllSpinners();

    const homeserverInput = document.getElementById('homeserver');
    const resetHsInput = document.getElementById('resetHomeserver');
    const hsGroup = document.getElementById('hsGroup');
    if(!homeserverInput || !hsGroup) return;

    homeserverInput.value = server;
    if (resetHsInput) resetHsInput.value = server;
    clearError(homeserverInput);
    closeDropdown();
    updateActiveServerHighlight();
    hsGroup.classList.add('force-blur');
    const removeBlur = () => { hsGroup.classList.remove('force-blur'); document.removeEventListener('mousemove', removeBlur); };
    document.addEventListener('mousemove', removeBlur);
}


function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    if(!input) return;

    btn.textContent = '';

    if (input.type === 'password') {
        input.type = 'text';
        input.style.fontFamily = 'var(--font-family)';
        input.style.letterSpacing = 'normal';
        btn.appendChild(createSvgIcon('eyeOpen', { width: '20', height: '20' }));
        btn.setAttribute('aria-label', t('ariaHidePassword', 'Hide password'));
        btn.setAttribute('aria-pressed', 'true');
    } else {
        input.type = 'password';
        input.style.fontFamily = 'system-ui, -apple-system, sans-serif';
        input.style.letterSpacing = '3px';
        btn.appendChild(createSvgIcon('eyeClosed', { width: '20', height: '20' }));
        btn.setAttribute('aria-label', t('ariaShowPassword', 'Show password'));
        btn.setAttribute('aria-pressed', 'false');
    }
}

async function handleServerSubmit(e) {
    e.preventDefault(); hideGlobalError();
    const homeserverInput = document.getElementById('homeserver');
    if(!homeserverInput) return;

    let hs = homeserverInput.value.trim();
    if (!checkField('homeserver', hs.length > 0, 'errRequired')) return;

    const signal = getNewAuthSignal();
    setButtonLoading('btnServerNext', true);

    try {
        currentBaseUrl = await getBaseUrl(hs, signal);
        const res = await fetch(`${currentBaseUrl}/_matrix/client/v3/login`, { signal });
        if (res.ok) {
            const data = await res.json(); const flows = data.flows || [];
            serverSupportsSSO = flows.some(f => f.type === 'm.login.sso' || f.type === 'm.login.cas');
            serverSupportsPassword = flows.some(f => f.type === 'm.login.password');
        } else { serverSupportsSSO = false; serverSupportsPassword = true; }

        configureCredentialsStep();
        goToStep('stepCredentials');

    } catch (e) {
        if (e.name === 'AbortError') return;
        showGlobalError('errServerNetwork');
    } finally {
        if (!signal.aborted) {
            setButtonLoading('btnServerNext', false);
        }
    }
}


function configureCredentialsStep() {
    const ssoWrap = document.getElementById('ssoWrap');
    const ssoDivider = document.getElementById('ssoDivider');
    const manualWrap = document.getElementById('manualAuthWrap');
    const emailGroup = document.getElementById('emailGroup');
    const confirmGroup = document.getElementById('confirmPasswordGroup');
    const forgotWrap = document.getElementById('forgotLinkWrap');
    const ssoExpl = document.getElementById('ssoExplBox');
    const authSub = document.getElementById('txtAuthSub');
    const strengthWrap = document.getElementById('passwordStrengthWrap');

    if(!ssoWrap) return;
    if (emailGroup) emailGroup.classList.add('hidden');

    if (currentFlow === 'login') {
        confirmGroup.classList.add('hidden');
        forgotWrap.classList.remove('hidden');
        if(strengthWrap) strengthWrap.classList.add('hidden');
    } else {
        confirmGroup.classList.remove('hidden');
        forgotWrap.classList.add('hidden');
        if(strengthWrap) strengthWrap.classList.remove('hidden');
    }

    if (serverSupportsSSO && serverSupportsPassword) {
        ssoWrap.style.display = 'flex';
        ssoDivider.style.display = 'flex';
        manualWrap.style.display = 'flex';
        ssoExpl.classList.add('hidden');
        authSub.style.display = 'block';
    } else if (serverSupportsSSO && !serverSupportsPassword) {
        ssoWrap.style.display = 'flex';
        ssoDivider.style.display = 'none';
        manualWrap.style.display = 'none';
        ssoExpl.classList.remove('hidden');
        authSub.style.display = 'none';
    } else {
        ssoWrap.style.display = 'none';
        manualWrap.style.display = 'flex';
        ssoExpl.classList.add('hidden');
        authSub.style.display = 'block';
    }

    updatePasswordAutocomplete();
    updatePasswordStrength(document.getElementById('password')?.value || '');
}


async function handleSSO() {
    hideGlobalError();
    setButtonLoading('ssoBtn', true);

    try {
        const homeserverInput = document.getElementById('homeserver');
        const hs = homeserverInput?.value.trim() || getDisplayServerName(currentBaseUrl);

        const ssoState = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2);
        sessionStorage.setItem('e2e_sso_state', ssoState);
        localStorage.setItem(PENDING_HS_KEY, hs);

        const redirectUrl = encodeURIComponent(`${window.location.origin}${window.location.pathname}?sso_state=${ssoState}`);
        window.location.href = `${currentBaseUrl}/_matrix/client/v3/login/sso/redirect?redirectUrl=${redirectUrl}`;
    } catch (e) {
        showGlobalError('errServerNetwork');
        setButtonLoading('ssoBtn', false);
    }
}


async function handleAuthSubmit(e) {
    e.preventDefault();
    hideGlobalError();
    let isValid = true;
    const userVal = document.getElementById('username').value.trim();
    if (!checkField('username', userVal.length > 0, 'errRequired')) isValid = false;

    const passVal = document.getElementById('password').value;
    if (!checkField('password', passVal.length > 0, 'errRequired')) isValid = false;

    if (currentFlow === 'register' && isValid) {
        const confirmVal = document.getElementById('confirmPassword').value;
        if (!checkField('confirmPassword', confirmVal.length > 0, 'errRequired')) isValid = false;
        else if (!checkField('confirmPassword', passVal === confirmVal, 'errPasswordMatch')) isValid = false;
    }

    if (!isValid) return;

    const signal = getNewAuthSignal();
    setButtonLoading('btnAuthSubmit', true);

    try {
        let effectiveBaseUrl = currentBaseUrl;
        const mxid = parseMatrixIdentifier(userVal);
        if (currentFlow === 'login' && mxid?.server) {
            const selectedServer = normalizeHomeserverInput(document.getElementById('homeserver')?.value || '');
            if (mxid.server.toLowerCase() !== selectedServer.toLowerCase()) {
                effectiveBaseUrl = await getBaseUrl(mxid.server, signal);
                currentBaseUrl = effectiveBaseUrl;
                rememberHomeserver(effectiveBaseUrl);
                showGlobalError('msgUsingMxidServer', 'info');
            }
        }

        let data;
        if (currentFlow === 'login') {
            data = await matrixLogin(effectiveBaseUrl, userVal, passVal, signal);
        } else {
            data = await matrixRegister(effectiveBaseUrl, userVal, passVal, signal);
        }

        await SecureSession.save({
            baseUrl: effectiveBaseUrl,
            userId: data.user_id,
            token: data.access_token,
            refreshToken: data.refresh_token || null
        });
        showAppScreen(effectiveBaseUrl, data.access_token);
    } catch (err) {
        if (err.name === 'AbortError') return;

        if (err instanceof MatrixError) {
            if (err.errcode === 'UIAA_SSO_ONLY') showGlobalError('errSSOOnlyReg');
            else if (err.errcode === 'UIAA_UNSUPPORTED') showGlobalError('errVerificationNeeded');
            else if (err.errcode === 'M_LIMIT_EXCEEDED') showGlobalError('errTooManyRequests');
            else if (err.errcode === 'M_USER_IN_USE') showGlobalError('errUserExists');
            else if (err.errcode === 'M_FORBIDDEN' && /disabled/i.test(err.message)) showGlobalError('errRegDisabled');
            else if (err.errcode === 'M_FORBIDDEN' || err.errcode === 'M_INVALID_USERNAME') showGlobalError('errInvalidAuth');
            else if (err.errcode === 'M_UNKNOWN_TOKEN' && err.softLogout) showGlobalError('errSessionExpired', 'info');
            else showGlobalError(err.message);
        } else if (err.message === 'Failed to fetch') {
            showGlobalError('errServerNetwork');
        } else {
            showGlobalError(err.message);
        }
    } finally {
        if (!signal.aborted) {
            setButtonLoading('btnAuthSubmit', false);
        }
    }
}


async function handleResetSubmit(e) {
    e.preventDefault();
    hideGlobalError();

    let isValid = true;
    const hsVal = document.getElementById('resetHomeserver').value.trim();
    if (!checkField('resetHomeserver', hsVal.length > 0, 'errRequired')) isValid = false;

    const emailVal = document.getElementById('resetEmail').value.trim();
    if (emailVal.length === 0) isValid = checkField('resetEmail', false, 'errRequired');
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailVal)) isValid = checkField('resetEmail', false, 'errEmail');

    if (!isValid) return;

    const signal = getNewAuthSignal();
    setButtonLoading('btnResetSubmit', true);

    try {
        const resetBaseUrl = await getBaseUrl(hsVal, signal);
        await validateHomeserver(resetBaseUrl, signal);
        await requestPasswordReset(resetBaseUrl, emailVal, signal);
        rememberHomeserver(resetBaseUrl);
        showGlobalError('msgResetEmailSent', 'success');
        goToStep('stepCredentials');
    } catch (err) {
        if (err.name === 'AbortError') return;
        if (err instanceof MatrixError) {
            if (err.errcode === 'M_LIMIT_EXCEEDED') showGlobalError('errTooManyRequests');
            else if (err.errcode === 'M_THREEPID_DENIED' || err.errcode === 'M_NOT_FOUND') showGlobalError('errResetUnsupported');
            else showGlobalError('errServerNetwork');
        } else {
            showGlobalError('errServerNetwork');
        }
    } finally {
        if (!signal.aborted) {
            setButtonLoading('btnResetSubmit', false);
        }
    }
}

// Проверка Caps Lock
function checkCapsLock(e) {
    if (!e || typeof e.getModifierState !== 'function') return;

    const warnings = document.querySelectorAll('.caps-lock-warning');
    if (!warnings.length) return;

    const isCapsLockOn = e.getModifierState('CapsLock');

    warnings.forEach(warning => {
        if (isCapsLockOn) {
            warning.classList.remove('hidden');
        } else {
            warning.classList.add('hidden');
        }
    });
}

// Отслеживаем состояние при любом взаимодействии (нажатие клавиш или клик мышью)
document.addEventListener('keyup', checkCapsLock);
document.addEventListener('keydown', checkCapsLock);
document.addEventListener('mousedown', checkCapsLock);
document.addEventListener('click', checkCapsLock);


function ensurePasswordStrengthHelper() {
    let helper = document.getElementById('passwordStrengthText');
    if (!helper) {
        const wrap = document.getElementById('passwordStrengthWrap');
        if (!wrap || !wrap.parentNode) return null;
        helper = document.createElement('div');
        helper.id = 'passwordStrengthText';
        helper.className = 'helper-text hidden';
        helper.setAttribute('aria-live', 'polite');
        wrap.parentNode.insertBefore(helper, wrap.nextSibling);
    }
    return helper;
}

function updatePasswordStrength(value) {
    const wrap = document.getElementById('passwordStrengthWrap');
    const helper = ensurePasswordStrengthHelper();
    const bars = document.querySelectorAll('#passwordStrengthWrap .strength-bar');
    if (!wrap || !bars.length) return;

    if (currentFlow !== 'register') {
        wrap.classList.add('hidden');
        helper?.classList.add('hidden');
        bars.forEach(bar => { bar.style.background = 'var(--border)'; });
        return;
    }

    const val = String(value || '');
    wrap.classList.remove('hidden');
    helper?.classList.remove('hidden');

    let strength = 0;
    if (val.length >= 8) strength++;
    if (/[A-Z]/.test(val)) strength++;
    if (/[0-9]/.test(val)) strength++;
    if (/[^A-Za-z0-9]/.test(val)) strength++;

    const colors = ['var(--border)', 'var(--accent)', 'var(--accent)', '#ffffff', '#ffffff'];
    bars.forEach((bar, index) => {
        bar.style.background = index < strength ? colors[strength] : 'var(--border)';
    });

    const strengthKeys = ['pwdStrengthWeak', 'pwdStrengthWeak', 'pwdStrengthFair', 'pwdStrengthGood', 'pwdStrengthStrong'];
    if (helper) {
        helper.textContent = val.length === 0 ? t('pwdStrengthHint', 'Use 8+ characters, uppercase letters, numbers and symbols.') : t(strengthKeys[strength], 'Password strength');
    }
}

function updatePasswordAutocomplete() {
    const passwordInput = document.getElementById('password');
    const confirmInput = document.getElementById('confirmPassword');
    if (passwordInput) {
        passwordInput.setAttribute('autocomplete', currentFlow === 'register' ? 'new-password' : 'current-password');
    }
    if (confirmInput) {
        confirmInput.setAttribute('autocomplete', currentFlow === 'register' ? 'new-password' : 'off');
    }
}

function initializeAccessibility() {
    const toastContainer = document.getElementById('toastContainer');
    if (toastContainer) {
        toastContainer.setAttribute('aria-live', 'polite');
        toastContainer.setAttribute('aria-atomic', 'false');
        toastContainer.setAttribute('role', 'region');
    }

    const syncText = document.getElementById('syncText');
    if (syncText) syncText.setAttribute('aria-live', 'polite');

    const dropdownButton = document.getElementById('btnDropdownToggle');
    if (dropdownButton) {
        dropdownButton.removeAttribute('tabindex');
        dropdownButton.setAttribute('aria-label', t('ariaToggleServerList', 'Toggle homeserver suggestions'));
        dropdownButton.setAttribute('aria-haspopup', 'listbox');
        dropdownButton.setAttribute('aria-expanded', 'false');
    }

    const menu = document.getElementById('hsMenu');
    if (menu) menu.setAttribute('role', 'listbox');
    document.querySelectorAll('.dropdown-item[data-server]').forEach(item => {
        item.setAttribute('role', 'option');
        item.setAttribute('tabindex', '0');
        item.setAttribute('aria-selected', 'false');
    });

    ['btnEyePassword', 'btnEyeConfirm'].forEach(id => {
        const button = document.getElementById(id);
        if (button) {
            button.removeAttribute('tabindex');
            button.setAttribute('aria-label', t('ariaShowPassword', 'Show password'));
            button.setAttribute('aria-pressed', 'false');
        }
    });

    document.querySelectorAll('.input-group').forEach(group => {
        const input = group.querySelector('.input-field');
        const error = group.querySelector('.error-text');
        if (input && error) {
            if (!error.id) error.id = `${input.id || 'field'}-error`;
            input.setAttribute('aria-describedby', error.id);
            input.setAttribute('aria-invalid', 'false');
        }
    });
}

// --- DOM & EVENT BINDINGS ---
function bindEvents() {
    document.getElementById('btnLogout')?.addEventListener('click', performLogout);
    document.getElementById('btnLangToggle')?.addEventListener('click', openLangModal);
    document.getElementById('btnLangClose')?.addEventListener('click', closeLangModalBtn);
    document.getElementById('langModalOverlay')?.addEventListener('click', (e) => {
        if(e.target.id === 'langModalOverlay') closeLangModalBtn();
    });
    document.getElementById('btnLangClear')?.addEventListener('click', () => {
        const searchInput = document.getElementById('langSearch');
        if (searchInput) {
            searchInput.value = '';
            filterLanguages();
            searchInput.focus();
        }
    });

    document.getElementById('btnStartLogin')?.addEventListener('click', () => startFlow('login'));
    document.getElementById('btnStartReg')?.addEventListener('click', () => startFlow('register'));

    document.getElementById('btnBackToWelcome')?.addEventListener('click', () => { abortAuthRequests(); resetAllSpinners(); goToStep('stepWelcome'); });
    document.getElementById('btnBackToServer')?.addEventListener('click', () => { abortAuthRequests(); resetAllSpinners(); goToStep('stepServer'); });
    document.getElementById('btnBackToAuth')?.addEventListener('click', () => { abortAuthRequests(); resetAllSpinners(); goToStep('stepCredentials'); });

    document.getElementById('lnkForgot')?.addEventListener('click', (e) => { e.preventDefault(); goToStep('stepReset'); });

    document.getElementById('ssoBtn')?.addEventListener('click', handleSSO);

    document.getElementById('homeserver')?.addEventListener('input', function() { handleInput(this); });
    document.getElementById('homeserver')?.addEventListener('focus', openDropdown);
    document.getElementById('btnDropdownToggle')?.addEventListener('click', toggleDropdown);

    document.querySelectorAll('.srv-select').forEach(el => {
        el.addEventListener('click', function() { selectServer(this.getAttribute('data-server')); });
    });

    document.addEventListener('click', (e) => {
        const hsGroup = document.getElementById('hsGroup');
        if (hsGroup && !hsGroup.contains(e.target)) closeDropdown(e);
    });

    document.getElementById('btnEyePassword')?.addEventListener('click', function() { togglePasswordVisibility('password', this); });
    document.getElementById('btnEyeConfirm')?.addEventListener('click', function() { togglePasswordVisibility('confirmPassword', this); });

    document.getElementById('formServer')?.addEventListener('submit', handleServerSubmit);
    document.getElementById('formAuth')?.addEventListener('submit', handleAuthSubmit);
    document.getElementById('formReset')?.addEventListener('submit', handleResetSubmit);

    ['username', 'email', 'password', 'confirmPassword', 'resetHomeserver', 'resetEmail'].forEach(id => {
        document.getElementById(id)?.addEventListener('input', function() { clearError(this); });
    });

    document.getElementById('langSearch')?.addEventListener('input', filterLanguages);

    // Привязка Caps Lock
    document.addEventListener('keyup', checkCapsLock);
    document.addEventListener('keydown', checkCapsLock);

    // Привязка индикатора пароля
    document.getElementById('password')?.addEventListener('input', function() {
        if (currentFlow !== 'register') return;

        const val = this.value;
        const bars = document.querySelectorAll('#passwordStrengthWrap .strength-bar');
        if (!bars.length) return;

        let strength = 0;
        if (val.length >= 8) strength++;
        if (/[A-Z]/.test(val)) strength++;
        if (/[0-9]/.test(val)) strength++;
        if (/[^A-Za-z0-9]/.test(val)) strength++;

        const colors = ['var(--border)', 'var(--accent)', 'var(--accent)', '#ffffff', '#ffffff'];

        bars.forEach((bar, index) => {
            bar.style.background = index < strength ? colors[strength] : 'var(--border)';
        });
    });
}

function getVisibleInputs() {
    return Array.from(document.querySelectorAll('.input-field:not(.search-field)')).filter(el => {
        const group = el.closest('.input-group');
        return group && !group.classList.contains('hidden') && el.offsetParent !== null;
    });
}

function focusNextField(currentInput) {
    const visibleInputs = getVisibleInputs();
    const index = visibleInputs.indexOf(currentInput);
    const nextInput = index > -1 ? visibleInputs[index + 1] || null : null;
    if (!nextInput) return false;
    nextInput.focus({ preventScroll: true });
    return true;
}

function updateDropdownHighlight(items) {
    items.forEach((item, index) => {
        if (index === currentDropdownIndex) {
            item.classList.add('active');
            item.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            document.getElementById('homeserver').value = item.getAttribute('data-server');
        } else {
            item.classList.remove('active');
        }
    });
}

document.addEventListener('keydown', function(e) {
    const hsGroup = document.getElementById('hsGroup');
    const hsMenu = document.getElementById('hsMenu');

    // Управление дропдауном с клавиатуры
    if (hsGroup && hsGroup.classList.contains('open') && e.target.id === 'homeserver') {
        const items = Array.from(hsMenu.querySelectorAll('.dropdown-item'));

        if (e.key === 'ArrowDown') {
            e.preventDefault();
            currentDropdownIndex = (currentDropdownIndex + 1) % items.length;
            updateDropdownHighlight(items);
            return;
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            currentDropdownIndex = (currentDropdownIndex - 1 + items.length) % items.length;
            updateDropdownHighlight(items);
            return;
        } else if (e.key === 'Enter') {
            e.preventDefault();
            if (currentDropdownIndex >= 0) {
                selectServer(items[currentDropdownIndex].getAttribute('data-server'));
            } else {
                closeDropdown();
                document.getElementById('btnServerNext')?.click();
            }
            return;
        } else if (e.key === 'Escape') {
            closeDropdown();
            return;
        }
    }

    // Стандартное переключение полей
    if (e.key === 'Enter' || e.keyCode === 13) {
        if (hsGroup && hsGroup.classList.contains('open')) { closeDropdown(); }
        if (e.target.tagName === 'INPUT' && !e.target.classList.contains('search-field')) {
            e.preventDefault();
            if (window.innerWidth <= 1125 && e.target.id === 'homeserver') { e.target.blur(); return; }
            const moved = focusNextField(e.target);
            if (!moved) {
                e.target.blur();
                if (activeStep === 'stepServer') document.getElementById('btnServerNext')?.click();
                else if (activeStep === 'stepCredentials') document.getElementById('btnAuthSubmit')?.click();
                else if (activeStep === 'stepReset') document.getElementById('btnResetSubmit')?.click();
            }
        }
    }
});

let cachedThemeColors = null; let cachedInputs = null;
function refreshAutofillStyles() {
    if (!cachedThemeColors) {
        const rs = getComputedStyle(document.documentElement);
        cachedThemeColors = { text: rs.getPropertyValue('--text-main').trim() || '#ffffff', bg: rs.getPropertyValue('--bg-base').trim() || '#0b0b0d', font: rs.getPropertyValue('--font-family').trim() || 'sans-serif' };
    }
    if (!cachedInputs) { cachedInputs = document.querySelectorAll('.input-field:not(.search-field)'); }
    requestAnimationFrame(() => {
        cachedInputs.forEach(input => {
            input.style.color = cachedThemeColors.text; input.style.webkitTextFillColor = cachedThemeColors.text;
            input.style.textShadow = `0 0 0 ${cachedThemeColors.text}`; input.style.backgroundColor = cachedThemeColors.bg;
            if (input.type === 'password') { input.style.fontFamily = 'system-ui, -apple-system, sans-serif'; input.style.letterSpacing = '3px'; }
            else { input.style.fontFamily = cachedThemeColors.font; input.style.letterSpacing = 'normal'; }
        });
    });
}

window.addEventListener('pageshow', () => { refreshAutofillStyles(); setTimeout(refreshAutofillStyles, 100); });
const handleInputEvents = (e) => { if (e.target.classList && e.target.classList.contains('input-field')) { refreshAutofillStyles(); } };
document.addEventListener('focusin', handleInputEvents, { passive: true });
document.addEventListener('input', handleInputEvents, { passive: true });
document.addEventListener('change', handleInputEvents, { passive: true });

let resizeTimer;
window.addEventListener('resize', () => {
    document.body.classList.add('is-resizing'); clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { document.body.classList.remove('is-resizing'); }, 100);
});

// --- BOOTSTRAP ---
window.addEventListener('DOMContentLoaded', () => {
    try {
        bindEvents();
        currentLangCode = detectLanguage();
        renderLanguagesInitial();
        initializeAccessibility();
        ensurePasswordStrengthHelper();
        updateUI();
        refreshAutofillStyles();
        updateActiveServerHighlight();
    } catch (e) {
        console.error('Bootstrap init failed', e);
        finishBoot(document.getElementById('preloader'));
    }
});


window.addEventListener('load', async () => {
    const preloader = document.getElementById('preloader');

    try {
        const urlParams = new URLSearchParams(window.location.search);
        const loginToken = urlParams.get('loginToken');
        const returnedState = urlParams.get('sso_state');

        if (loginToken) {
            const savedState = sessionStorage.getItem('e2e_sso_state');
            sessionStorage.removeItem('e2e_sso_state');

            window.history.replaceState({}, document.title, window.location.pathname);

            if (!returnedState || returnedState !== savedState) {
                console.error('SSO State mismatch. Possible CSRF.');
                localStorage.removeItem(PENDING_HS_KEY);
                showGlobalError('errInvalidSsoState');
                setTimeout(() => finishBoot(preloader), 600);
                return;
            }

            const pendingHs = localStorage.getItem(PENDING_HS_KEY);
            if (pendingHs) {
                try {
                    const baseUrl = await getBaseUrl(pendingHs);
                    const data = await matrixTokenLogin(baseUrl, loginToken);
                    await SecureSession.save({
                        baseUrl,
                        userId: data.user_id,
                        token: data.access_token,
                        refreshToken: data.refresh_token || null
                    });
                    localStorage.removeItem(PENDING_HS_KEY);
                    showAppScreen(baseUrl, data.access_token);
                    setTimeout(() => finishBoot(preloader), 600);
                    return;
                } catch (e) {
                    console.warn('SSO token login failed', e);
                }
            }
        }

        const session = await SecureSession.load();
        if (session) {
            const readySession = await ensureSessionReady(session);
            if (readySession) {
                showAppScreen(readySession.baseUrl, readySession.token);
            } else {
                console.warn('Stored token is invalid or expired. Clearing session.');
                await SecureSession.clear();
            }
        }
    } catch (e) {
        console.error('Boot load failed', e);
        try { showGlobalError('errServerNetwork'); } catch (_) {}
    } finally {
        setTimeout(() => finishBoot(preloader), 600);
        refreshAutofillStyles();
        setTimeout(refreshAutofillStyles, 100);
    }
});


window.addEventListener('pageshow', () => {
    resetAllSpinners();
    refreshAutofillStyles();
    setTimeout(refreshAutofillStyles, 100);
});