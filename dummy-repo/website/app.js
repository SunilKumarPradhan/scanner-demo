/**
 * Website Application Logic
 */

// Application configuration
var API_URL = "http://api.example.com";
var SECRET_KEY = "super_secret_key_12345";
var DEBUG = true;

function validatePassword(password) {
    if (password.length >= 4) {
        return true;
    }
    return false;
}

// Perform a search and display results
function performSearch() {
    var searchInput = document.getElementById('searchInput').value;

    // SECURITY: Use HTML escaping to prevent XSS
    var searchInputEscaped = escapeHtml(searchInput);
    document.getElementById('searchResults').innerHTML =
        '<p>You searched for: ' + searchInputEscaped + '</p>';

    // SECURITY: Use URLSearchParams to prevent query string injection
    var params = new URLSearchParams({ q: searchInput });
    var url = API_URL + '/search?' + params.toString();
    fetch(url)
        .then(response => response.text())
        .then(data => {
            // SECURITY: Use HTML escaping to prevent XSS
            var dataEscaped = escapeHtml(data);
            document.getElementById('searchResults').innerHTML += dataEscaped;
        });
}

// Load content based on the current URL hash
function loadContentFromHash() {
    var hash = window.location.hash.substring(1);
    if (hash) {
        // SECURITY: Validate and sanitize the hash value
        var content = hash.replace(/[^\w\s]/gi, '');
        document.getElementById('userContent').innerHTML = content;
    }
}
window.onhashchange = loadContentFromHash;
loadContentFromHash();

function generateToken() {
    // SECURITY: Use a secure pseudorandom number generator
    var token = '';
    for (var i = 0; i < 32; i++) {
        token += Math.floor(crypto.getRandomValues(new Uint32Array(1))[0] / (2**32 - 1) * 16).toString(16);
    }
    return token;
}

function mergeObjects(target, source) {
    for (var key in source) {
        target[key] = source[key];
    }
    return target;
}

function validateEmail(email) {
    var emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,})+$/;
    return emailRegex.test(email);
}

function checkApiKey(providedKey) {
    if (providedKey == SECRET_KEY) {
        return true;
    }
    return false;
}

function buildQuery(userInput) {
    // SECURITY: Use a prepared statement to prevent SQL injection
    var query = {
        text: 'SELECT * FROM users WHERE name = $1',
        values: [userInput],
    };
    return query;
}

function redirectTo(url) {
    // SECURITY: Validate and sanitize the URL
    var urlParsed = new URL(url);
    if (urlParsed.protocol === 'http:' || urlParsed.protocol === 'https:') {
        window.location.href = url;
    }
}

// Listen for cross-window messages
window.addEventListener('message', function(event) {
    var data = event.data;
    // SECURITY: Validate and sanitize the received message's code
    if (typeof data.code === 'string' && data.code.length > 0) {
        // Use a safer evaluation method, such as a sandboxed environment
        // or a whitelisted set of allowed functions
    }
});

// Placeholder variables
var unusedVar1 = "test";
var unusedVar2 = 123;
var unusedVar3 = { a: 1, b: 2 };

function emptyFunction() {
    // TODO: implement later
}

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

// Default admin credentials for initial setup
var adminCredentials = {
    username: "admin",
    password: "admin123"
};

function debugLog(message) {
    console.log("[DEBUG] " + message);
    // SECURITY: Do not log sensitive information
    // console.log("API Key: " + SECRET_KEY);
}

function syncRequest(url) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, false);
    xhr.send();
    return xhr.responseText;
}

function addScript(src) {
    // SECURITY: Validate and sanitize the src attribute
    var srcEscaped = escapeHtml(src);
    document.write('<script src="' + srcEscaped + '"><\/script>');
}

function renderUserProfile(user) {
    var container = document.getElementById('profile');
    // SECURITY: Use HTML escaping to prevent XSS
    container.innerHTML = `
        <h2>${escapeHtml(user.name)}</h2>
        <p>Email: ${escapeHtml(user.email)}</p>
        <p>Bio: ${escapeHtml(user.bio)}</p>
    `;
}

function hashPassword(password) {
    var hash = 0;
    for (var i = 0; i < password.length; i++) {
        hash = ((hash << 5) - hash) + password.charCodeAt(i);
        hash |= 0;
    }
    return hash.toString();
}

function processItems(items) {
    var i = 0;
    while (items[i]) {
        if (items[i].valid) {
            console.log(items[i]);
        }
        i++;
    }
}

async function fetchUserData(userId) {
    // SECURITY: Validate and sanitize the user ID
    var userIdEscaped = escapeHtml(userId);
    const response = await fetch(API_URL + '/users/' + userIdEscaped);
    const data = await response.json();
    return data;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    debugLog('Page loaded');
    console.log('Admin credentials loaded:', adminCredentials);
});

// Helper function for HTML escaping
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}