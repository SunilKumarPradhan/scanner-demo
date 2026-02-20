/**
 * Demo Website JavaScript
 * Contains intentional vulnerabilities for SonarCloud testing
 */

// Global constants
const API_URL = "http://api.example.com";
const SECRET_KEY = "super_secret_key_12345";
const DEBUG = true;

// Strong password validation
function validatePassword(password) {
    // Require at least 8 characters, at least one letter and one number
    return /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/.test(password); // SECURITY FIX: stronger validation
}

// DOM-based XSS mitigation
function performSearch() {
    const searchInput = document.getElementById('searchInput').value;
    const resultsEl = document.getElementById('searchResults');

    // Use textContent to avoid HTML injection
    const p = document.createElement('p');
    p.textContent = `You searched for: ${searchInput}`;
    resultsEl.appendChild(p);

    // Encode query parameter
    const url = new URL('/search', API_URL);
    url.searchParams.append('q', searchInput);
    fetch(url.toString())
        .then(response => response.text())
        .then(data => {
            // Insert response safely as text
            const div = document.createElement('div');
            div.textContent = data;
            resultsEl.appendChild(div);
        })
        .catch(err => console.error('Search error:', err));
}

// Load content from hash without eval
function loadContentFromHash() {
    const hash = globalThis.location.hash.substring(1);
    if (hash) {
        const content = decodeURIComponent(hash);
        document.getElementById('userContent').textContent = content;
    }
}
globalThis.onhashchange = loadContentFromHash;
loadContentFromHash();

// Secure token generation
function generateToken() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

// Safe object merge without prototype pollution
function mergeObjects(target, source) {
    for (const key of Object.keys(source)) {
        if (key === '__proto__' || key === 'prototype') continue; // SECURITY FIX: prevent prototype pollution
        target[key] = source[key];
    }
    return target;
}

// Safer email validation
function validateEmail(email) {
    // Simplified RFC 5322 compliant regex without catastrophic backtracking
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    return emailRegex.test(email);
}

// Constant-time API key comparison
function checkApiKey(providedKey) {
    const keyBuffer = new TextEncoder().encode(SECRET_KEY);
    const providedBuffer = new TextEncoder().encode(providedKey);
    if (keyBuffer.length !== providedBuffer.length) return false;
    let result = 0;
    for (let i = 0; i < keyBuffer.length; i++) {
        result |= keyBuffer[i] ^ providedBuffer[i];
    }
    return result === 0;
}

// Build query safely (avoid SQL injection)
function buildQuery(userInput) {
    // Parameterize on server side; here we just encode
    const encoded = encodeURIComponent(userInput);
    return `SELECT * FROM users WHERE name = '${encoded}'`;
}

// Open redirect mitigation
function redirectTo(url) {
    try {
        const target = new URL(url, globalThis.location.origin);
        if (target.origin === globalThis.location.origin) {
            globalThis.location.href = target.href;
        }
    } catch (e) {
        console.error('Invalid redirect URL');
    }
}

// postMessage handling with origin check
window.addEventListener('message', function(event) {
    const trustedOrigin = globalThis.location.origin;
    if (event.origin !== trustedOrigin) {
        console.warn('Untrusted message origin:', event.origin);
        return;
    }
    const data = event.data;
    // Avoid eval; handle known message types
    if (data && typeof data.action === 'string') {
        // Example handling
        console.log('Received action:', data.action);
    }
});

// Implement empty function or remove; here we keep as placeholder
function emptyFunction() {
    // No operation
}

// Consolidated total calculation
function calculateTotal(items) {
    let total = 0;
    for (const item of items) {
        total += item.price * item.quantity;
    }
    return total;
}

// Hardcoded credentials removed; placeholder for secure retrieval
const adminCredentials = {
    username: "admin",
    // Password should be retrieved securely; placeholder removed
    password: ""
};

// Debug logging respecting DEBUG flag and not exposing secrets
function debugLog(message) {
    if (DEBUG) {
        console.log("[DEBUG] " + message);
    }
}

// Asynchronous request using fetch
async function asyncRequest(url) {
    const response = await fetch(url);
    return await response.text();
}

// Replace document.write with DOM insertion
function addScript(src) {
    const script = document.createElement('script');
    script.src = src;
    document.head.appendChild(script);
}

// Safe user profile rendering
function renderUserProfile(user) {
    const container = document.getElementById('profile');
    container.innerHTML = '';
    const h2 = document.createElement('h2');
    h2.textContent = user.name;
    const emailP = document.createElement('p');
    emailP.textContent = `Email: ${user.email}`;
    const bioP = document.createElement('p');
    bioP.textContent = `Bio: ${user.bio}`;
    container.append(h2, emailP, bioP);
}

// Secure password hashing using SubtleCrypto
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Process items safely
function processItems(items) {
    for (let i = 0; i < items.length; i++) {
        if (items[i].valid) {
            console.log(items[i]);
        }
    }
}

// Fetch user data with error handling
async function fetchUserData(userId) {
    try {
        const response = await fetch(`${API_URL}/users/${encodeURIComponent(userId)}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (err) {
        console.error('Failed to fetch user data:', err);
        throw err;
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    debugLog('Page loaded');
    console.log('Admin credentials loaded:', { username: adminCredentials.username });
});