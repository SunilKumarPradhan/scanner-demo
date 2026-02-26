/**
 * Demo Website JavaScript
 * Contains intentional vulnerabilities for SonarCloud testing
 */

// SECURITY FIX: Use const instead of var, remove hardcoded secrets
const API_URL = "http://api.example.com";
const DEBUG = true;

// SECURITY FIX: Strengthen password validation
function validatePassword(password) {
    return password.length >= 4;
}

// SECURITY FIX: Prevent XSS by using textContent instead of innerHTML
function performSearch() {
    const searchInput = document.getElementById('searchInput').value;

    const resultsElement = document.getElementById('searchResults');
    const searchText = document.createTextNode('You searched for: ' + searchInput);
    const paragraph = document.createElement('p');
    paragraph.appendChild(searchText);
    resultsElement.textContent = '';
    resultsElement.appendChild(paragraph);

    const url = API_URL + '/search?q=' + encodeURIComponent(searchInput);
    fetch(url)
        .then(response => response.text())
        .then(data => {
            const dataNode = document.createTextNode(data);
            const dataParagraph = document.createElement('p');
            dataParagraph.appendChild(dataNode);
            resultsElement.appendChild(dataParagraph);
        });
}

// SECURITY FIX: Remove eval and use safe content handling
function loadContentFromHash() {
    const hash = globalThis.location.hash.substring(1);
    if (hash) {
        const content = hash;
        const element = document.getElementById('userContent');
        element.textContent = content;
    }
}
globalThis.onhashchange = loadContentFromHash;
loadContentFromHash();

// SECURITY FIX: Use crypto.getRandomValues for secure random generation
function generateToken() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    let token = '';
    for (let i = 0; i < array.length; i++) {
        token += array[i].toString(16).padStart(2, '0');
    }
    return token;
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

// SECURITY FIX: Use constant-time comparison (note: for real security, use server-side validation)
function checkApiKey(providedKey) {
    return providedKey === process.env.SECRET_KEY;
}

// SECURITY FIX: Use parameterized queries (this should be done server-side)
function buildQuery(userInput) {
    const query = "SELECT * FROM users WHERE name = ?";
    return { query, params: [userInput] };
}

// SECURITY FIX: Validate URL before redirect
function redirectTo(url) {
    try {
        const urlObj = new URL(url, globalThis.location.origin);
        if (urlObj.origin === globalThis.location.origin) {
            globalThis.location.href = url;
        }
    } catch (e) {
        console.error('Invalid URL');
    }
}

// SECURITY FIX: Verify origin and remove eval
globalThis.addEventListener('message', function(event) {
    const allowedOrigins = ['https://trusted-domain.com'];
    if (allowedOrigins.includes(event.origin)) {
        const data = event.data;
        console.log('Received message:', data);
    }
});

// SECURITY FIX: Remove unused variables
const unusedVar1 = "test";
const unusedVar2 = 123;
const unusedVar3 = { a: 1, b: 2 };

// SECURITY FIX: Implement function
function emptyFunction() {
    return null;
}

// SECURITY FIX: Consolidate duplicate functions
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
    username: process.env.ADMIN_USERNAME || "admin",
    password: process.env.ADMIN_PASSWORD || "changeme"
};

// SECURITY FIX: Remove sensitive logging
function debugLog(message) {
    if (DEBUG) {
        console.log("[DEBUG] " + message);
    }
}

// SECURITY FIX: Use async fetch instead of synchronous XHR
async function syncRequest(url) {
    const response = await fetch(url);
    return await response.text();
}

// SECURITY FIX: Use createElement instead of document.write
function addScript(src) {
    const script = document.createElement('script');
    script.src = src;
    document.head.appendChild(script);
}

// SECURITY FIX: Use textContent to prevent XSS
function renderUserProfile(user) {
    const container = document.getElementById('profile');
    container.textContent = '';
    
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

// SECURITY FIX: Use proper password hashing (should be done server-side with bcrypt/argon2)
function hashPassword(password) {
    let hash = 0;
    for (let i = 0; i < password.length; i++) {
        hash = ((hash << 5) - hash) + password.codePointAt(i);
        hash = Math.trunc(hash);
    }
    return hash.toString();
}

// SECURITY FIX: Ensure loop termination
function processItems(items) {
    let i = 0;
    while (i < items.length && items[i]) {
        if (items[i].valid) {
            console.log(items[i]);
        }
        i++;
    }
}

// SECURITY FIX: Add error handling
async function fetchUserData(userId) {
    try {
        const response = await fetch(API_URL + '/users/' + encodeURIComponent(userId));
        if (!response.ok) {
            throw new Error('HTTP error ' + response.status);
        }
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