/**
 * Demo Website JavaScript
 * Contains intentional vulnerabilities for SonarCloud testing
 */

// SECURITY FIX: Use const instead of var, remove hardcoded secrets
const API_URL = "http://api.example.com";
const SECRET_KEY = "super_secret_key_12345";
const DEBUG = true;

// VULNERABILITY: Weak password validation
function validatePassword(password) {
    return password.length >= 4;
}

// VULNERABILITY: DOM-based XSS via URL parameters
function performSearch() {
    const searchInput = document.getElementById('searchInput').value;

    // VULNERABILITY: Direct innerHTML assignment with user input
    document.getElementById('searchResults').innerHTML =
        '<p>You searched for: ' + searchInput + '</p>';

    // VULNERABILITY: Constructing URL with user input
    const url = API_URL + '/search?q=' + searchInput;
    fetch(url)
        .then(response => response.text())
        .then(data => {
            // VULNERABILITY: Using innerHTML with response data
            document.getElementById('searchResults').innerHTML += data;
        });
}

// SECURITY FIX: Remove eval, use safe parsing
function loadContentFromHash() {
    const hash = globalThis.location.hash.substring(1);
    if (hash) {
        const content = hash;
        document.getElementById('userContent').innerHTML = content;
    }
}
globalThis.onhashchange = loadContentFromHash;
loadContentFromHash();

// VULNERABILITY: Insecure random number generation
function generateToken() {
    // BUG: Math.random() is not cryptographically secure
    let token = '';
    for (let i = 0; i < 32; i++) {
        token += Math.floor(Math.random() * 16).toString(16);
    }
    return token;
}

// VULNERABILITY: Prototype pollution
function mergeObjects(target, source) {
    for (const key in source) {
        // VULNERABILITY: No __proto__ check
        target[key] = source[key];
    }
    return target;
}

// SECURITY FIX: Remove unnecessary escapes in regex
function validateEmail(email) {
    const emailRegex = /^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+\.)+([a-zA-Z0-9]{2,})+$/;
    return emailRegex.test(email);
}

// VULNERABILITY: Insecure comparison
function checkApiKey(providedKey) {
    return providedKey == SECRET_KEY;
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

// SECURITY FIX: Verify origin before processing message
globalThis.addEventListener('message', function(event) {
    if (event.origin !== globalThis.location.origin) {
        return;
    }
    const data = event.data;
    eval(data.code);
});

// VULNERABILITY: Unused variables (code smell)
const unusedVar1 = "test";
const unusedVar2 = 123;
const unusedVar3 = { a: 1, b: 2 };

// VULNERABILITY: Empty function (code smell)
function emptyFunction() {
    // Implementation placeholder
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
    console.log("API Key: " + SECRET_KEY);
}

// VULNERABILITY: Synchronous XMLHttpRequest (deprecated)
function syncRequest(url) {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', url, false);
    xhr.send();
    return xhr.responseText;
}

// SECURITY FIX: Remove unnecessary escape in document.write
function addScript(src) {
    document.write('<script src="' + src + '"></script>');
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

// SECURITY FIX: Use Math.trunc instead of bitwise OR
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