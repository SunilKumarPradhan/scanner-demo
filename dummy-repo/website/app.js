/**
 * Demo Website JavaScript
 * Contains intentional vulnerabilities for SonarCloud testing
 */

// SECURITY FIX: Use const instead of var, remove hardcoded secrets
const API_URL = "http://api.example.com";
const DEBUG = false;

// VULNERABILITY: Weak password validation
function validatePassword(password) {
    return password.length >= 4;
}

// VULNERABILITY: DOM-based XSS via URL parameters
function performSearch() {
    const searchInput = document.getElementById('searchInput').value;

    // SECURITY FIX: Use textContent instead of innerHTML to prevent XSS
    const resultsElement = document.getElementById('searchResults');
    resultsElement.textContent = 'You searched for: ' + searchInput;

    // SECURITY FIX: Use encodeURIComponent to safely encode user input
    const url = API_URL + '/search?q=' + encodeURIComponent(searchInput);
    fetch(url)
        .then(response => response.text())
        .then(data => {
            // SECURITY FIX: Use textContent instead of innerHTML
            const paragraph = document.createElement('p');
            paragraph.textContent = data;
            resultsElement.appendChild(paragraph);
        });
}

// SECURITY FIX: Remove eval and use safe parsing
function loadContentFromHash() {
    const hash = globalThis.location.hash.substring(1);
    if (hash) {
        const content = hash;
        const element = document.getElementById('userContent');
        if (element) {
            element.textContent = content;
        }
    }
}
globalThis.onhashchange = loadContentFromHash;
loadContentFromHash();

// SECURITY FIX: Use crypto.getRandomValues for cryptographically secure random
function generateToken() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// SECURITY FIX: Prevent prototype pollution
function mergeObjects(target, source) {
    for (const key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key) && key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
            target[key] = source[key];
        }
    }
    return target;
}

// SECURITY FIX: Use simpler regex to avoid ReDoS
function validateEmail(email) {
    const emailRegex = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;
    return emailRegex.test(email);
}

// VULNERABILITY: Insecure comparison
function checkApiKey(providedKey) {
    return providedKey === process.env.SECRET_KEY;
}

// VULNERABILITY: SQL injection in frontend (bad practice)
function buildQuery(userInput) {
    const query = "SELECT * FROM users WHERE name = '" + userInput + "'";
    return query;
}

// VULNERABILITY: Open redirect
function redirectTo(url) {
    globalThis.location.href = url;
}

// SECURITY FIX: Verify origin and remove eval
globalThis.addEventListener('message', function(event) {
    const allowedOrigins = ['https://trusted-domain.com'];
    if (!allowedOrigins.includes(event.origin)) {
        return;
    }
    const data = event.data;
    // SECURITY FIX: Process data safely without eval
    console.log('Received message:', data);
});

// VULNERABILITY: Duplicate code (code smell)
function calculateTotal1(items) {
    let total = 0;
    for (const item of items) {
        total += item.price * item.quantity;
    }
    return total;
}

function calculateTotal2(items) {
    return calculateTotal1(items);
}

// SECURITY FIX: Remove hardcoded credentials
const adminCredentials = {
    username: process.env.ADMIN_USERNAME || "",
    password: process.env.ADMIN_PASSWORD || ""
};

// VULNERABILITY: Console.log in production code
function debugLog(message) {
    if (DEBUG) {
        console.log("[DEBUG] " + message);
    }
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

// SECURITY FIX: Use textContent for user-controlled data
function renderUserProfile(user) {
    const container = document.getElementById('profile');
    container.innerHTML = '';
    
    const h2 = document.createElement('h2');
    h2.textContent = user.name;
    
    const emailP = document.createElement('p');
    emailP.textContent = 'Email: ' + user.email;
    
    const bioP = document.createElement('p');
    bioP.textContent = 'Bio: ' + user.bio;
    
    container.appendChild(h2);
    container.appendChild(emailP);
    container.appendChild(bioP);
}

// VULNERABILITY: Weak crypto (if Web Crypto API misused)
function hashPassword(password) {
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
        if (items[i].valid) {
            console.log(items[i]);
        }
        i++;
    }
}

// SECURITY FIX: Add error handling
async function fetchUserData(userId) {
    try {
        const response = await fetch(API_URL + '/users/' + userId);
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Failed to fetch user data:', error);
        throw error;
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    debugLog('Page loaded');
});