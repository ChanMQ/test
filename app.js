// --- FRAMEBUSTING & SECURITY INIT ---
if (self === top) {
    const antiClickjack = document.getElementById('antiClickjack');
    if (antiClickjack) antiClickjack.remove();
} else {
    top.location = self.location;
}

if (window.fallbackTimer) clearTimeout(window.fallbackTimer);

// --- SECURE SESSION MODULE (INDEXEDDB + WEBCRYPTO) ---
const SecureSession = (function() {
    const DB_NAME = 'E2ENetworkDB';
    const DB_VERSION = 3; // Обновлена схема
    const STORE_NAME = 'secure_session';

    function openDB() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(DB_NAME, DB_VERSION);
            req.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    db.createObjectStore(STORE_NAME);
                } else {
                    // Safe clear on upgrade for structure refresh
                    db.deleteObjectStore(STORE_NAME);
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
                            { name: "AES-GCM", length: 256 },
                            false,
                            ["encrypt", "decrypt"]
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

    async function save(baseUrl, userId, tokenData) {
        try {
            const db = await openDB();
            const key = await getOrGenerateKey(db);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const payload = JSON.stringify(typeof tokenData === 'string' ? { access_token: tokenData } : tokenData);
            const encodedToken = new TextEncoder().encode(payload);

            const ciphertext = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv },
                key,
                encodedToken
            );

            await new Promise((resolve, reject) => {
                const tx = db.transaction(STORE_NAME, 'readwrite');
                const store = tx.objectStore(STORE_NAME);
                store.put({ baseUrl, userId, iv, ciphertext }, 'session_data');
                tx.oncomplete = () => resolve();
                tx.onerror = () => reject(tx.error);
            });
        } catch (e) {
            console.error("Session save failed", e);
        }
    }

    async function load() {
        try {
            const db = await openDB();
            return await new Promise((resolve, reject) => {
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
                            { name: "AES-GCM", iv: data.iv },
                            key,
                            data.ciphertext
                        );
                        const decoded = new TextDecoder().decode(decrypted);
                        let payload;
                        try {
                            payload = JSON.parse(decoded);
                        } catch(e) {
                            payload = { access_token: decoded };
                        }
                        resolve({ baseUrl: data.baseUrl, userId: data.userId, ...payload });
                    } catch (e) {
                        console.warn("Decryption failed. Clearing corrupted data.");
                        await clear();
                        resolve(null);
                    }
                };
                tx.onerror = () => reject(tx.error);
            });
        } catch (e) {
            return null;
        }
    }

    async function clear() {
        try {
            const db = await openDB();
            await new Promise((resolve) => {
                const tx = db.transaction(STORE_NAME, 'readwrite');
                const store = tx.objectStore(STORE_NAME);
                store.delete('session_data');
                // Keep crypto_key to avoid re-generating
                tx.oncomplete = () => resolve();
            });
        } catch(e) {}
        localStorage.removeItem('matrix_pending_hs');
    }

    return { save, load, clear };
})();

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
    svg.setAttribute("aria-hidden", "true");

    Object.entries(props).forEach(([k, v]) => svg.setAttribute(k, v));

    data.forEach(el => {
        const child = document.createElementNS("http://www.w3.org/2000/svg", el.tag);
        Object.entries(el.attrs).forEach(([k, v]) => child.setAttribute(k, v));
        svg.appendChild(child);
    });
    return svg;
}

// --- MATRIX CLIENT LOGIC & STATE ---
let syncAbortController = null;
let syncTimeoutId = null;
let syncNextBatch = null;
let syncRetryCount = 0;
let currentDropdownIndex = -1;

let appState = { isActive: false };
let activeStep = 'stepWelcome';
let currentFlow = 'login';
let currentBaseUrl = '';
let serverSupportsSSO = false;
let serverSupportsPassword = true;

let authAbortController = null;
let emailRegState = { clientSecret: null, sid: null, session: null };

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

async function resolveHomeserver(input, signal) {
    let domain = input.trim();
    if (domain.startsWith('@')) {
        const parts = domain.split(':');
        if (parts.length > 1) domain = parts[1];
    }
    domain = domain.replace(/^https?:\/\//, '').replace(/\/$/, '');

    try {
        const res = await fetch(`https://${domain}/.well-known/matrix/client`, { signal });
        if (res.ok) {
            const data = await res.json();
            if (data['m.homeserver'] && data['m.homeserver'].base_url) {
                return data['m.homeserver'].base_url.replace(/\/$/, '');
            }
        }
    } catch (e) {
        if (e.name === 'AbortError') throw e;
    }

    try {
        const verRes = await fetch(`https://${domain}/_matrix/client/versions`, { signal });
        if (verRes.ok) return `https://${domain}`;
    } catch(e) {
        if (e.name === 'AbortError') throw e;
    }
    return `https://${domain}`;
}

async function matrixLogin(baseUrl, username, password, signal) {
    const res = await fetch(`${baseUrl}/_matrix/client/v3/login`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            type: 'm.login.password',
            identifier: { type: 'm.id.user', user: username },
            password: password,
            initial_device_display_name: 'e2e.network Web',
            refresh_token: true
        }),
        signal: signal
    });
    if (res.status === 429) throw new Error('M_LIMIT_EXCEEDED');
    if (!res.ok) { const err = await res.json().catch(() => ({})); throw new Error(err.errcode || err.error || 'Login failed'); }
    return res.json();
}

async function matrixRegister(baseUrl, username, password, email, signal) {
    let res = await fetch(`${baseUrl}/_matrix/client/v3/register`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, initial_device_display_name: 'e2e.network Web', refresh_token: true }),
        signal: signal
    });
    if (res.status === 200) return res.json();
    if (res.status === 429) throw new Error('M_LIMIT_EXCEEDED');

    if (res.status === 401) {
        const uiaa = await res.json();
        const session = uiaa.session;
        const flows = uiaa.flows || [];

        let hasDummy = flows.some(f => f.stages.includes('m.login.dummy'));
        let hasEmail = flows.some(f => f.stages.includes('m.login.email.identity'));

        if (flows.some(f => f.stages.includes('m.login.terms'))) throw new Error('M_TERMS_REQUIRED');
        if (flows.some(f => f.stages.includes('m.login.registration_token'))) throw new Error('M_REGISTRATION_TOKEN_REQUIRED');

        if (hasEmail && email) {
            if (!emailRegState.clientSecret) {
                emailRegState.clientSecret = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2);
                const emailRes = await fetch(`${baseUrl}/_matrix/client/v3/register/email/requestToken`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ client_secret: emailRegState.clientSecret, email: email, send_attempt: 1 }),
                    signal
                });
                if (!emailRes.ok) throw await emailRes.json();
                emailRegState.sid = (await emailRes.json()).sid;
                emailRegState.session = session;
                throw new Error('EMAIL_CHECK_REQUIRED');
            } else {
                res = await fetch(`${baseUrl}/_matrix/client/v3/register`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username, password, initial_device_display_name: 'e2e.network Web', refresh_token: true,
                        auth: { type: 'm.login.email.identity', session: session, threepidCreds: { sid: emailRegState.sid, client_secret: emailRegState.clientSecret } }
                    }),
                    signal
                });
                if (!res.ok) throw await res.json();
                emailRegState = { clientSecret: null, sid: null, session: null };
                return res.json();
            }
        }

        if (hasDummy && !email) {
            res = await fetch(`${baseUrl}/_matrix/client/v3/register`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, initial_device_display_name: 'e2e.network Web', refresh_token: true, auth: { type: 'm.login.dummy', session: session } }),
                signal: signal
            });
            if (!res.ok) throw await res.json();
            return res.json();
        }

        throw new Error('UIAA_NOT_SUPPORTED');
    }
    throw new Error('Registration failed');
}

async function matrixRequestPasswordReset(baseUrl, email, signal) {
    const clientSecret = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2);
    const res = await fetch(`${baseUrl}/_matrix/client/v3/account/password/email/requestToken`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_secret: clientSecret, email: email, send_attempt: 1 }),
        signal
    });
    if (!res.ok) throw await res.json();
    return true;
}

async function tryRefreshToken() {
    const session = await SecureSession.load();
    if (!session || !session.refresh_token) return null;
    try {
        const res = await fetch(`${session.baseUrl}/_matrix/client/v3/refresh`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: session.refresh_token })
        });
        if (res.ok) {
            const data = await res.json();
            await SecureSession.save(session.baseUrl, session.userId, data);
            return data;
        }
    } catch(e) {}
    return null;
}

async function verifyToken(baseUrl, token) {
    try {
        const res = await fetch(`${baseUrl}/_matrix/client/v3/account/whoami`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) return true;
        if (res.status === 401) {
            const err = await res.json();
            if (err.errcode === 'M_UNKNOWN_TOKEN' && !err.soft_logout) {
                const refreshed = await tryRefreshToken();
                return !!refreshed;
            }
        }
        return false;
    } catch (e) {
        return false;
    }
}

async function startMatrixSync(baseUrl, accessToken) {
    if (!accessToken || !appState.isActive) return;
    document.getElementById('syncText').textContent = getDict().syncing || 'Syncing with Matrix...';
    try {
        const syncUrl = new URL(`${baseUrl}/_matrix/client/v3/sync`);
        syncUrl.searchParams.append('timeout', '30000');
        if (syncNextBatch) syncUrl.searchParams.append('since', syncNextBatch);

        syncAbortController = new AbortController();
        const res = await fetch(syncUrl, { headers: { 'Authorization': `Bearer ${accessToken}` }, signal: syncAbortController.signal });

        if (res.ok) {
            syncRetryCount = 0;
            const data = await res.json();
            syncNextBatch = data.next_batch;
            document.getElementById('syncText').textContent = getDict().synced || 'Synced';
            if (appState.isActive) {
                syncTimeoutId = setTimeout(() => startMatrixSync(baseUrl, accessToken), 100);
            }
        } else if (res.status === 401) {
            const err = await res.json();
            if (err.errcode === 'M_UNKNOWN_TOKEN' && err.soft_logout) {
                handleSoftLogout();
            } else if (err.errcode === 'M_UNKNOWN_TOKEN') {
                const refreshed = await tryRefreshToken();
                if (refreshed) startMatrixSync(baseUrl, refreshed.access_token);
                else performLogout(true);
            } else {
                handleSyncRetry(baseUrl, accessToken);
            }
        } else {
            handleSyncRetry(baseUrl, accessToken);
        }
    } catch (e) {
        if (e.name !== 'AbortError' && appState.isActive) {
            handleSyncRetry(baseUrl, accessToken);
        }
    }
}

function handleSyncRetry(baseUrl, accessToken) {
    if (!appState.isActive) return;
    let delay = Math.min(2000 * Math.pow(2, syncRetryCount), 60000);
    syncRetryCount++;
    document.getElementById('syncText').textContent = (getDict().syncError || 'Connection error. Retrying in') + ` ${delay/1000}s...`;
    syncTimeoutId = setTimeout(() => startMatrixSync(baseUrl, accessToken), delay);
}

function handleSoftLogout() {
    appState.isActive = false;
    if (syncAbortController) { syncAbortController.abort(); syncAbortController = null; }
    if (syncTimeoutId) { clearTimeout(syncTimeoutId); syncTimeoutId = null; }
    showGlobalError('msgSessionExpired');
    document.getElementById('appContainer').classList.remove('active');
    document.getElementById('authContainer').style.display = 'flex';
    goToStep('stepCredentials');
}

function showAppScreen(baseUrl, accessToken) {
    appState.isActive = true;
    document.getElementById('authContainer').style.display = 'none';
    document.getElementById('appContainer').classList.add('active');
    startMatrixSync(baseUrl, accessToken);
}

async function performLogout(forced = false) {
    appState.isActive = false;
    if (syncAbortController) { syncAbortController.abort(); syncAbortController = null; }
    if (syncTimeoutId) { clearTimeout(syncTimeoutId); syncTimeoutId = null; }

    const session = await SecureSession.load();
    if (session && session.access_token && !forced) {
        try {
            await fetch(`${session.baseUrl}/_matrix/client/v3/logout`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${session.access_token}` }
            });
        } catch(e) {}
    }

    await SecureSession.clear();
    syncNextBatch = null;

    document.getElementById('appContainer').classList.remove('active');
    document.getElementById('authContainer').style.display = 'flex';
    document.getElementById('password').value = '';
    document.getElementById('confirmPassword').value = '';
    goToStep('stepWelcome');
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
    const savedLang = localStorage.getItem('e2e_preferred_lang');
    if (savedLang && availableCodes.includes(savedLang)) return savedLang;
    if (navigator.language) {
        const browserLang = navigator.language.toLowerCase();
        if (availableCodes.includes(browserLang)) return browserLang;
        const shortLang = browserLang.split('-')[0];
        if (availableCodes.includes(shortLang)) return shortLang;
    }
    return 'en';
}

function getDict() {
    const dict = i18n[currentLangCode] || {};
    const fallback = i18n['en'] || {};
    return { ...fallback, ...dict };
}

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
    const text = getDict();
    const activeLangObj = languages.find(l => l.code === currentLangCode) || languages.find(l => l.code === 'en');

    document.documentElement.lang = currentLangCode;
    document.documentElement.dir = ['ar', 'he', 'fa'].includes(currentLangCode) ? 'rtl' : 'ltr';

    if (activeLangObj) safeSetText('currentLangBtnText', activeLangObj.name);

    const searchInput = document.getElementById('langSearch');
    if (searchInput) searchInput.placeholder = text.searchPlace || 'Search...';

    safeSetText('btnLangCloseText', text.btnClose || 'Close');

    safeSetText('txtWelcomeTitle', text.welcomeTitle);
    safeSetText('txtWelcomeSub', text.welcomeSub);
    safeSetText('btnWelcomeLogin', text.btnWelcomeLogin);
    safeSetText('btnWelcomeReg', text.btnWelcomeReg);

    safeSetText('txtServerTitle', text.titleServer);
    safeSetText('txtServerSub', currentFlow === 'login' ? text.subServerLogin : text.subServerReg);
    safeSetText('lblHomeserver', text.lblHomeserver);
    safeSetText('txtPopularServers', text.txtPopularServers);
    safeSetText('txtBtnNext', text.btnNext);

    safeSetText('txtAuthTitle', currentFlow === 'login' ? text.titleAuthLogin : text.titleAuthReg);
    safeSetText('txtAuthSub', text.subAuth);
    safeSetText('lblUsername', currentFlow === 'login' ? text.lblUsernameLogin : text.lblUsernameReg);
    safeSetText('lblEmail', text.lblEmail);
    safeSetText('lblPassword', currentFlow === 'login' ? text.lblPasswordLogin : text.lblPasswordReg);
    safeSetText('lblConfirm', text.lblConfirm);
    safeSetText('lnkForgot', text.lnkForgot);
    safeSetText('txtBtnAuthSubmit', currentFlow === 'login' ? text.btnAuthLogin : text.btnAuthReg);

    const iconWrap = document.getElementById('primaryIconWrap');
    if (iconWrap) {
        iconWrap.textContent = '';
        iconWrap.appendChild(createSvgIcon(currentFlow === 'login' ? 'login' : 'register', { width: "20", height: "20" }));
    }

    if (text.ssoText) safeSetText('btnSsoText', text.ssoText);
    if (text.ssoOr) safeSetText('ssoDivider', text.ssoOr);
    if (text.ssoOnlyExpl) safeSetText('txtSsoOnlyExpl', text.ssoOnlyExpl);

    safeSetText('txtResetTitle', text.titleReset);
    safeSetText('txtResetSub', text.subReset);
    safeSetText('lblResetHs', "Homeserver");
    safeSetText('lblResetEmail', text.lblEmail);
    safeSetText('txtBtnResetSubmit', text.btnSendReset);
}

function startFlow(flow) {
    currentFlow = flow;
    emailRegState = { clientSecret: null, sid: null, session: null };
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
}

function removeToast(toast) {
    if (!toast.classList.contains('active')) return;
    toast.classList.remove('active');
    setTimeout(() => toast.remove(), 300);
}

function showGlobalError(msgKey, type = 'error') {
    const text = getDict();
    const msg = text[msgKey] || msgKey;
    const container = document.getElementById('toastContainer');
    if(!container) return;

    const existingToasts = container.querySelectorAll('.toast-item');
    if (existingToasts.length >= 3) { existingToasts[0].remove(); }

    const toast = document.createElement('div');
    toast.className = `toast-item toast-${type}`;

    const iconSpan = document.createElement('span');
    iconSpan.className = 'toast-icon';
    iconSpan.appendChild(createSvgIcon(type === 'success' ? 'success' : type === 'info' ? 'info' : 'error', { width: "18", height: "18", "stroke-width": "2.5" }));

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
    }, 5000);

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
    const errText = group.querySelector('.error-text');
    if (!condition) {
        group.classList.remove('invalid'); void group.offsetWidth;
        group.classList.add('invalid');
        if(errText) errText.textContent = getDict()[msgKey] || msgKey;
        return false;
    }
    return true;
}

function openDropdown() {
    const hsGroup = document.getElementById('hsGroup');
    if(hsGroup) hsGroup.classList.add('open');
}

function closeDropdown(e) {
    if(e) e.stopPropagation();
    const hsGroup = document.getElementById('hsGroup');
    if(hsGroup) hsGroup.classList.remove('open');
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
        if (item.getAttribute('data-server').toLowerCase() === currentVal) { item.classList.add('active'); } else { item.classList.remove('active'); }
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
    const hsGroup = document.getElementById('hsGroup');
    if(!homeserverInput || !hsGroup) return;

    homeserverInput.value = server;
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
        btn.appendChild(createSvgIcon('eyeOpen', { width: "20", height: "20" }));
    } else {
        input.type = 'password';
        input.style.fontFamily = 'system-ui, -apple-system, sans-serif';
        input.style.letterSpacing = '3px';
        btn.appendChild(createSvgIcon('eyeClosed', { width: "20", height: "20" }));
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
        currentBaseUrl = await resolveHomeserver(hs, signal);
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

    if (currentFlow === 'login') {
        emailGroup.classList.add('hidden'); confirmGroup.classList.add('hidden'); forgotWrap.classList.remove('hidden');
        if(strengthWrap) strengthWrap.classList.add('hidden');
    } else {
        emailGroup.classList.remove('hidden'); confirmGroup.classList.remove('hidden'); forgotWrap.classList.add('hidden');
        if(strengthWrap) strengthWrap.classList.remove('hidden');
    }

    if (serverSupportsSSO && serverSupportsPassword) {
        ssoWrap.style.display = 'flex'; ssoDivider.style.display = 'flex'; manualWrap.style.display = 'flex';
        ssoExpl.classList.add('hidden'); authSub.style.display = 'block';
    } else if (serverSupportsSSO && !serverSupportsPassword) {
        ssoWrap.style.display = 'flex'; ssoDivider.style.display = 'none'; manualWrap.style.display = 'none';
        ssoExpl.classList.remove('hidden'); authSub.style.display = 'none';
    } else {
        ssoWrap.style.display = 'none'; manualWrap.style.display = 'flex';
        ssoExpl.classList.add('hidden'); authSub.style.display = 'block';
    }
}

async function handleSSO() {
    hideGlobalError();
    setButtonLoading('ssoBtn', true);

    try {
        const homeserverInput = document.getElementById('homeserver');
        let hs = homeserverInput.value.trim();

        const ssoState = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2);
        sessionStorage.setItem('e2e_sso_state', ssoState);
        localStorage.setItem('matrix_pending_hs', hs);

        let redirectUrl = encodeURIComponent(window.location.origin + window.location.pathname + '?sso_state=' + ssoState);
        window.location.href = `${currentBaseUrl}/_matrix/client/v3/login/sso/redirect?redirectUrl=${redirectUrl}`;
    } catch (e) {
        showGlobalError('errServerNetwork');
        setButtonLoading('ssoBtn', false);
    }
}

function mapMatrixError(msgKey) {
    if (msgKey.includes('m_user_in_use')) return 'errUserExists';
    if (msgKey.includes('m_forbidden') || msgKey.includes('m_invalid_username')) return 'errInvalidAuth';
    if (msgKey.includes('m_limit_exceeded')) return 'errTooManyRequests';
    if (msgKey.includes('m_terms_required')) return 'errUIAATerms';
    if (msgKey.includes('m_registration_token_required')) return 'errUIAARegToken';
    if (msgKey.includes('email_check_required')) return 'msgCheckEmail';
    if (msgKey.includes('m_unknown_token')) return 'errUnknownToken';
    if (msgKey.includes('registration has been disabled')) return 'errRegDisabled';
    if (msgKey === 'sso_only') return 'errSSOOnlyReg';
    return null;
}

async function handleAuthSubmit(e) {
    e.preventDefault(); hideGlobalError();
    let isValid = true;
    const userVal = document.getElementById('username').value.trim();
    const emailVal = document.getElementById('email').value.trim();
    if (!checkField('username', userVal.length > 0, 'errRequired')) isValid = false;

    if (currentFlow === 'register') {
        if (emailVal.length > 0 && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailVal)) { isValid = checkField('email', false, 'errEmail'); }
    }

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
        let data;
        if (currentFlow === 'login') {
            data = await matrixLogin(currentBaseUrl, userVal, passVal, signal);
        } else {
            data = await matrixRegister(currentBaseUrl, userVal, passVal, emailVal, signal);
        }

        await SecureSession.save(currentBaseUrl, data.user_id, data);
        showAppScreen(currentBaseUrl, data.access_token);

    } catch (err) {
        if (err.name === 'AbortError') return;

        let msg = (err.errcode || err.message || err.error || '').toLowerCase();
        let mapped = mapMatrixError(msg);

        if (mapped === 'msgCheckEmail') {
            showGlobalError('msgCheckEmail', 'info');
        } else if (mapped) {
            showGlobalError(mapped);
        } else if (msg === 'failed to fetch' || msg.includes('network')) {
            showGlobalError('errServerNetwork');
        } else {
            showGlobalError(err.error || err.message);
        }
    } finally {
        if (!signal.aborted) {
            setButtonLoading('btnAuthSubmit', false);
        }
    }
}

async function handleResetSubmit(e) {
    e.preventDefault(); hideGlobalError();

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
        const targetBase = await resolveHomeserver(hsVal, signal);
        await matrixRequestPasswordReset(targetBase, emailVal, signal);
        showGlobalError('msgResetEmailSent', 'success');
        goToStep('stepCredentials');

    } catch (err) {
        if (err.name === 'AbortError') return;
        let msg = (err.errcode || err.message || '').toLowerCase();
        let mapped = mapMatrixError(msg);
        showGlobalError(mapped || 'errServerNetwork');
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

document.addEventListener('keyup', checkCapsLock);
document.addEventListener('keydown', checkCapsLock);
document.addEventListener('mousedown', checkCapsLock);
document.addEventListener('click', checkCapsLock);

// --- DOM & EVENT BINDINGS ---
function bindEvents() {
    document.getElementById('btnLogout')?.addEventListener('click', () => performLogout());
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
    bindEvents();
    currentLangCode = detectLanguage();
    renderLanguagesInitial();
    updateUI();
    refreshAutofillStyles();
    updateActiveServerHighlight();

    if (window.fallbackTimer) clearTimeout(window.fallbackTimer);
});

window.addEventListener('load', async () => {
    const preloader = document.getElementById('preloader');

    const urlParams = new URLSearchParams(window.location.search);
    const loginToken = urlParams.get('loginToken');
    const returnedState = urlParams.get('sso_state');

    if (loginToken) {
        const savedState = sessionStorage.getItem('e2e_sso_state');
        sessionStorage.removeItem('e2e_sso_state');

        window.history.replaceState({}, document.title, window.location.pathname);

        if (!returnedState || returnedState !== savedState) {
            console.error("SSO State mismatch. Possible CSRF.");
            localStorage.removeItem('matrix_pending_hs');
            showGlobalError('Error: Invalid SSO Session State');
            setTimeout(() => { preloader.classList.add('hidden'); document.body.classList.remove('loading'); }, 600);
            return;
        }

        const pendingHs = localStorage.getItem('matrix_pending_hs');
        if (pendingHs) {
            try {
                const baseUrl = await resolveHomeserver(pendingHs);
                const res = await fetch(`${baseUrl}/_matrix/client/v3/login`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: 'm.login.token', token: loginToken, initial_device_display_name: 'e2e.network Web' })
                });
                if (res.ok) {
                    const data = await res.json();
                    await SecureSession.save(baseUrl, data.user_id, data);
                    localStorage.removeItem('matrix_pending_hs');

                    const isValid = await verifyToken(baseUrl, data.access_token);
                    if (isValid) {
                        showAppScreen(baseUrl, data.access_token);
                        setTimeout(() => { preloader.classList.add('hidden'); document.body.classList.remove('loading'); }, 600);
                        return;
                    } else {
                        await SecureSession.clear();
                    }
                }
            } catch (e) {
                console.warn("SSO Token login failed", e);
            }
        }
    }

    const session = await SecureSession.load();
    if (session && session.access_token) {
        const isValid = await verifyToken(session.baseUrl, session.access_token);
        if (isValid) {
            const freshSession = await SecureSession.load();
            showAppScreen(freshSession.baseUrl, freshSession.access_token);
        } else {
            console.warn("Stored token is invalid or expired. Clearing session.");
            await SecureSession.clear();
        }
    }

    setTimeout(() => { preloader.classList.add('hidden'); document.body.classList.remove('loading'); }, 600);
    refreshAutofillStyles(); setTimeout(refreshAutofillStyles, 100);
});

window.addEventListener('pageshow', () => {
    resetAllSpinners();
    refreshAutofillStyles();
    setTimeout(refreshAutofillStyles, 100);
});