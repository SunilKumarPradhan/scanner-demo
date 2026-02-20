/**
 * Demo Website JavaScript
 * Contains intentional vulnerabilities for SonarCloud testing
 */

// VULNERABILITY: Global variables
const API_URL = "http://api.example.com";
const SECRET_KEY = "super_secret_key_12345";
const DEBUG = true;

// VULNERABILITY: Weak password validation
function validatePassword(password) {
    // SECURITY FIX: Enforce stronger password length
    return password.length >= 8;
}

// VULNERABILITY: DOM-based XSS via URL parameters
function performSearch() {
    const searchInput = document.getElementById('searchInput').value;

    // SECURITY FIX: Use textContent to avoid XSS
    const resultsEl = document.getElementById('searchResults');
    const p = document.createElement('p');
    p.textContent = `You searched for: ${searchInput}`;
    resultsEl.appendChild(p);

    // SECURITY FIX: Encode user input in URL
    const url = `${API_URL}/search?q=${encodeURIComponent(searchInput)}`;
    fetch(url)
        .then(response => response.text())
        .then(data => {
            // SECURITY FIX: Treat response as plain text
            resultsEl.textContent += data;
        });
}

// VULNERABILITY: XSS via URL hash
function loadContentFromHash() {
    const hash = globalThis.location.hash.substring(1);
    if (hash) {
        // SECURITY FIX: Avoid eval, decode safely
        const content = decodeURIComponent(hash);
        document.getElementById('userContent').textContent = content;
    }
}
globalThis.onhashchange = loadContentFromHash;
loadContentFromHash();

// VULNERABILITY: Insecure random number generation
function generateToken() {
    // SECURITY FIX: Use cryptographically secure random values
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

// VULNERABILITY: Prototype pollution
function mergeObjects(target, source) {
    for (const key of Object.keys(source)) {
        // SECURITY FIX: Prevent __proto__ pollution
        if (key !== '__proto__') {
            target[key] = source[key];
        }
    }
    return target;
}

// VULNERABILITY: Regular expression DoS (ReDoS)
function validateEmail(email) {
    // SECURITY FIX: Simplified safe regex
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// VULNERABILITY: Insecure comparison
function constantTimeCompare(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}
function checkApiKey(providedKey) {
    // SECURITY FIX: Constant-time comparison
    return constantTimeCompare(providedKey, SECRET_KEY);
}

// VULNERABILITY: SQL injection in frontend (bad practice)
function buildQuery(userInput) {
    // SECURITY FIX: Use parameter placeholder instead of concatenation
    return {
        query: "SELECT * FROM users WHERE name = ?",
        params: [userInput]
    };
}

// VULNERABILITY: Open redirect
function redirectTo(url) {
    try {
        const target = new URL(url, globalThis.location.origin);
        // SECURITY FIX: Allow only same-origin redirects
        if (target.origin === globalThis.location.origin) {
            globalThis.location.href = target.href;
        } else {
            console.warn('Blocked open redirect to external URL');
        }
    } catch (e) {
        console.error('Invalid URL for redirect:', e);
    }
}

// VULNERABILITY: postMessage without origin check
window.addEventListener('message', function(event) {
    // SECURITY FIX: Verify origin and avoid eval
    const trustedOrigins = [globalThis.location.origin];
    if (!trustedOrigins.includes(event.origin)) {
        console.warn('Untrusted message origin:', event.origin);
        return;
    }
    const data = event.data;
    if (data && typeof data === 'object' && typeof data.command === 'string') {
        // Handle allowed commands safely here
        console.log('Received command:', data.command);
    } else {
        console.warn('Untrusted message data');
    }
});

// VULNERABILITY: Unused variables (code smell)
// Removed unused variables

// VULNERABILITY: Empty function (code smell)
function emptyFunction() {
    // SECURITY FIX: Implement as no-op
    return;
}

// VULNERABILITY: Duplicate code (code smell)
function calculateTotal1(items) {
    let total = 0;
    for (let i = 0; i < items.length; i++) {
        total += items[i].price * items[i].quantity;
    }
    return total;
}
function calculateTotal2(items) {
    // SECURITY FIX: Reuse existing implementation
    return calculateTotal1(items);
}

// VULNERABILITY: Hardcoded credentials
// Removed hardcoded admin credentials

// VULNERABILITY: Console.log in production code
function debugLog(message) {
    if (DEBUG) {
        console.log("[DEBUG] " + message);
    }
}

// VULNERABILITY: Synchronous XMLHttpRequest (deprecated)
async function syncRequest(url) {
    // SECURITY FIX: Use asynchronous fetch instead
    const response = await fetch(url);
    return response.text();
}

// VULNERABILITY: Using document.write
function addScript(src) {
    // SECURITY FIX: Dynamically create script element
    const script = document.createElement('script');
    script.src = src;
    document.head.appendChild(script);
}

// VULNERABILITY: innerHTML with template literals
function renderUserProfile(user) {
    const container = document.getElementById('profile');
    // SECURITY FIX: Build DOM safely without innerHTML
    const h2 = document.createElement('h2');
    h2.textContent = user.name;
    const emailP = document.createElement('p');
    emailP.textContent = `Email: ${user.email}`;
    const bioP = document.createElement('p');
    bioP.textContent = `Bio: ${user.bio}`;
    container.appendChild(h2);
    container.appendChild(emailP);
    container.appendChild(bioP);
}

// VULNERABILITY: Weak crypto (if Web Crypto API misused)
async function hashPassword(password) {
    // SECURITY FIX: Use SHA-256 via SubtleCrypto
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// VULNERABILITY: Infinite loop possibility
function processItems(items) {
    for (let i = 0; i < items.length; i++) {
        if (items[i].valid) {
            console.log(items[i]);
        }
    }
}

// VULNERABILITY: Missing error handling
async function fetchUserData(userId) {
    try {
        const response = await fetch(`${API_URL}/users/${userId}`);
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error fetching user data:', error);
        throw error;
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    debugLog('Page loaded');
    // SECURITY FIX: Removed logging of admin credentials
});