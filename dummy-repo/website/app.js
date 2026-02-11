/**
 * Demo Website JavaScript
 * Contains intentional vulnerabilities for SonarCloud testing
 */

// VULNERABILITY: Global variables
var API_URL = "http://api.example.com";
var SECRET_KEY = "super_secret_key_12345";
var DEBUG = true;

// VULNERABILITY: Weak password validation
function validatePassword(password) {
    // BUG: Password only requires 4 characters
    if (password.length >= 4) {
        return true;
    }
    return false;
}

// VULNERABILITY: DOM-based XSS via URL parameters
function performSearch() {
    var searchInput = document.getElementById('searchInput').value;

    // VULNERABILITY: Direct innerHTML assignment with user input
    document.getElementById('searchResults').innerHTML =
        '<p>You searched for: ' + searchInput + '</p>';

    // VULNERABILITY: Constructing URL with user input
    var url = API_URL + '/search?q=' + searchInput;
    fetch(url)
        .then(response => response.text())
        .then(data => {
            // VULNERABILITY: Using innerHTML with response data
            document.getElementById('searchResults').innerHTML += data;
        });
}

// VULNERABILITY: XSS via URL hash
function loadContentFromHash() {
    var hash = window.location.hash.substring(1);
    if (hash) {
        // VULNERABILITY: eval with URL data
        eval('var content = "' + hash + '"');
        document.getElementById('userContent').innerHTML = content;
    }
}
window.onhashchange = loadContentFromHash;
loadContentFromHash();

// VULNERABILITY: Insecure random number generation
function generateToken() {
    // BUG: Math.random() is not cryptographically secure
    var token = '';
    for (var i = 0; i < 32; i++) {
        token += Math.floor(Math.random() * 16).toString(16);
    }
    return token;
}

// VULNERABILITY: Prototype pollution
function mergeObjects(target, source) {
    for (var key in source) {
        // VULNERABILITY: No __proto__ check
        target[key] = source[key];
    }
    return target;
}

// VULNERABILITY: Regular expression DoS (ReDoS)
function validateEmail(email) {
    // BUG: Vulnerable regex pattern
    var emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,})+$/;
    return emailRegex.test(email);
}

// VULNERABILITY: Insecure comparison
function checkApiKey(providedKey) {
    // BUG: Non-constant time comparison
    if (providedKey == SECRET_KEY) {
        return true;
    }
    return false;
}

// VULNERABILITY: SQL injection in frontend (bad practice)
function buildQuery(userInput) {
    // CODE SMELL: Building query strings in frontend
    var query = "SELECT * FROM users WHERE name = '" + userInput + "'";
    return query;
}

// VULNERABILITY: Open redirect
function redirectTo(url) {
    // VULNERABILITY: No URL validation
    window.location.href = url;
}

// VULNERABILITY: postMessage without origin check
window.addEventListener('message', function(event) {
    // VULNERABILITY: No origin verification
    var data = event.data;
    eval(data.code);  // CRITICAL: eval with message data
});

// VULNERABILITY: Unused variables (code smell)
var unusedVar1 = "test";
var unusedVar2 = 123;
var unusedVar3 = { a: 1, b: 2 };

// VULNERABILITY: Empty function (code smell)
function emptyFunction() {
    // TODO: implement later
}

// VULNERABILITY: Duplicate code (code smell)
function calculateTotal1(items) {
    var total = 0;
    for (var i = 0; i < items.length; i++) {
        total += items[i].price * items[i].quantity;
    }
    return total;
}

function calculateTotal2(items) {
    var total = 0;
    for (var i = 0; i < items.length; i++) {
        total += items[i].price * items[i].quantity;
    }
    return total;
}

// VULNERABILITY: Hardcoded credentials
var adminCredentials = {
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
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, false);  // Synchronous
    xhr.send();
    return xhr.responseText;
}

// VULNERABILITY: Using document.write
function addScript(src) {
    document.write('<script src="' + src + '"><\/script>');
}

// VULNERABILITY: innerHTML with template literals
function renderUserProfile(user) {
    var container = document.getElementById('profile');
    container.innerHTML = `
        <h2>${user.name}</h2>
        <p>Email: ${user.email}</p>
        <p>Bio: ${user.bio}</p>
    `;
}

// VULNERABILITY: Weak crypto (if Web Crypto API misused)
function hashPassword(password) {
    // BUG: Simple hash is not secure for passwords
    var hash = 0;
    for (var i = 0; i < password.length; i++) {
        hash = ((hash << 5) - hash) + password.charCodeAt(i);
        hash |= 0;
    }
    return hash.toString();
}

// VULNERABILITY: Infinite loop possibility
function processItems(items) {
    var i = 0;
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
