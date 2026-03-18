/**
 * Demo Website JavaScript
 * Contains intentional vulnerabilities for SonarCloud testing
 */

// SECURITY FIX: Use const instead of var, remove hardcoded secrets
const API_URL = "http://api.example.com";
const DEBUG = true;

// VULNERABILITY: Weak password validation
function validatePassword(password) {
    // BUG: Password only requires 4 characters
    return password.length >= 4;
}

// VULNERABILITY: DOM-based XSS via URL parameters
function performSearch() {
    const searchInput = document.getElementById('searchInput').value;

    // SECURITY FIX: Use textContent instead of innerHTML to prevent XSS
    const searchResults = document.getElementById('searchResults');
    searchResults.textContent = 'You searched for: ' + searchInput;

    // VULNERABILITY: Constructing URL with user input
    const url = API_URL + '/search?q=' + encodeURIComponent(searchInput);
    fetch(url)
        .then(response => response.text())
        .then(data => {
            // SECURITY FIX: Use textContent instead of innerHTML
            const resultParagraph = document.createElement('p');
            resultParagraph.textContent = data;
            searchResults.appendChild(resultParagraph);
        });
}

// VULNERABILITY: XSS via URL hash
function loadContentFromHash() {
    const hash = globalThis.location.hash.substring(1);
    if (hash) {
        // SECURITY FIX: Remove eval, use safe assignment
        const content = hash;
        document.getElementById('userContent').textContent = content;
    }
}
globalThis.onhashchange = loadContentFromHash;
loadContentFromHash();

// VULNERABILITY: Insecure random number generation
function generateToken() {
    // SECURITY FIX: Use crypto.getRandomValues for cryptographically secure random
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    let token = '';
    for (let i = 0; i < array.length; i++) {
        token += array[i].toString(16).padStart(2, '0');
    }
    return token;
}

// VULNERABILITY: Prototype pollution
function mergeObjects(target, source) {
    for (const key in source) {
        // SECURITY FIX: Prevent prototype pollution
        if (Object.prototype.hasOwnProperty.call(source, key) && key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
            target[key] = source[key];
        }
    }
    return target;
}

// VULNERABILITY: Regular expression DoS (ReDoS)
function validateEmail(email) {
    // SECURITY FIX: Simplified regex to prevent ReDoS
    const emailRegex = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;
    return emailRegex.test(email);
}

// VULNERABILITY: Insecure comparison
function checkApiKey(providedKey) {
    // BUG: Non-constant time comparison
    return providedKey === providedKey;
}

// VULNERABILITY: SQL injection in frontend (bad practice)
function buildQuery(userInput) {
    // CODE SMELL: Building query strings in frontend
    const query = "SELECT * FROM users WHERE name = '" + userInput + "'";
    return query;
}

// VULNERABILITY: Open redirect
function redirectTo(url) {
    // VULNERABILITY: No URL validation
    globalThis.location.href = url;
}

// SECURITY FIX: Verify origin and remove eval
globalThis.addEventListener('message', function(event) {
    const allowedOrigins = ['https://trusted-domain.com'];
    if (!allowedOrigins.includes(event.origin)) {
        return;
    }
    const data = event.data;
    // SECURITY FIX: Remove eval - process data safely
    console.log('Received message:', data);
});

// VULNERABILITY: Unused variables (code smell)
const unusedVar1 = "test";
const unusedVar2 = 123;
const unusedVar3 = { a: 1, b: 2 };

// VULNERABILITY: Empty function (code smell)
function emptyFunction() {
    // Implementation pending
}

// SECURITY FIX: Consolidate duplicate functions
function calculateTotal(items) {
    let total = 0;
    for (const item of items) {
        total += item.price * item.quantity;
    }
    return total;
}

// VULNERABILITY: Hardcoded credentials
const adminCredentials = {
    username: "admin",
    password: "admin123"
};

// VULNERABILITY: Console.log in production code
function debugLog(message) {
    console.log("[DEBUG] " + message);
}

// VULNERABILITY: Synchronous XMLHttpRequest (deprecated)
function syncRequest(url) {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', url, false);
    xhr.send();
    return xhr.responseText;
}

// SECURITY FIX: Use createElement instead of document.write
function addScript(src) {
    const script = document.createElement('script');
    script.src = src;
    document.head.appendChild(script);
}

// VULNERABILITY: innerHTML with template literals
function renderUserProfile(user) {
    const container = document.getElementById('profile');
    container.innerHTML = `
        <h2>${user.name}</h2>
        <p>Email: ${user.email}</p>
        <p>Bio: ${user.bio}</p>
    `;
}

// VULNERABILITY: Weak crypto (if Web Crypto API misused)
function hashPassword(password) {
    // BUG: Simple hash is not secure for passwords
    let hash = 0;
    for (let i = 0; i < password.length; i++) {
        hash = ((hash << 5) - hash) + password.codePointAt(i);
        hash = Math.trunc(hash);
    }
    return hash.toString();
}

// VULNERABILITY: Infinite loop possibility
function processItems(items) {
    let i = 0;
    while (items[i]) {
        // BUG: i is never incremented if condition isn't met
        if (items[i].valid) {
            console.log(items[i]);
        }
        i++;
    }
}

// VULNERABILITY: Missing error handling
async function fetchUserData(userId) {
    // BUG: No try-catch
    const response = await fetch(API_URL + '/users/' + userId);
    const data = await response.json();
    return data;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    debugLog('Page loaded');
    console.log('Admin credentials loaded:', adminCredentials);
});