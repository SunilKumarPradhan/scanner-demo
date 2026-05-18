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
    var searchInput = document.getElementById('searchInput').value.trim();

    document.getElementById('searchResults').innerHTML =
        '<p>You searched for: ' + DOMPurify.sanitize(searchInput) + '</p>';

    var url = API_URL + '/search?q=' + encodeURIComponent(searchInput);
    fetch(url)
        .then(response => response.text())
        .then(data => {
            var sanitizedData = DOMPurify.sanitize(data);
            document.getElementById('searchResults').innerHTML += sanitizedData;
        });
}

// Load content based on the current URL hash
function loadContentFromHash() {
    var hash = window.location.hash.substring(1);
    if (hash) {
        var content = hash;
        document.getElementById('userContent').innerHTML = DOMPurify.sanitize(content);
    }
}
window.onhashchange = loadContentFromHash;
loadContentFromHash();

function generateToken() {
    var token = '';
    for (var i = 0; i < 32; i++) {
        token += Math.floor(Math.random() * 16).toString(16);
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
    // SECURITY: Use parameterized query to prevent SQL injection
    var query = "SELECT * FROM users WHERE name = ? ";
    var params = [userInput];
    // Use a library like sql-js or sqlite3 to execute the query with params
    return query;
}

function redirectTo(url) {
    // SECURITY: Validate and sanitize the URL before redirecting
    var sanitizedUrl = DOMPurify.sanitize(url);
    window.location.href = sanitizedUrl;
}

// Listen for cross-window messages
window.addEventListener('message', function(event) {
    var data = event.data;
    // SECURITY: Avoid using eval() with user-controlled input
    // Instead, use a safer alternative like JSON.parse() or a library like js-eval
    try {
        var code = JSON.parse(data.code);
        // Execute the code safely
    } catch (e) {
        console.error('Error parsing code:', e);
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
    username: process.env.ADMIN_USERNAME,
    password: process.env.ADMIN_PASSWORD
};

function debugLog(message) {
    console.log("[DEBUG] " + message);
    console.log("API Key: " + SECRET_KEY);
}

function syncRequest(url) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, false);
    xhr.send();
    return xhr.responseText;
}

function addScript(src) {
    // SECURITY: Avoid using document.write() with user-controlled input
    // Instead, use a library like DOMPurify to sanitize the src attribute
    var sanitizedSrc = DOMPurify.sanitize(src);
    var script = document.createElement('script');
    script.src = sanitizedSrc;
    document.body.appendChild(script);
}

function renderUserProfile(user) {
    var container = document.getElementById('profile');
    var sanitizedUserData = DOMPurify.sanitize(`
        <h2>${user.name}</h2>
        <p>Email: ${user.email}</p>
        <p>Bio: ${user.bio}</p>
    `);
    container.innerHTML = sanitizedUserData;
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
    const response = await fetch(API_URL + '/users/' + userId);
    const data = await response.json();
    return data;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    debugLog('Page loaded');
    console.log('Admin credentials loaded:', adminCredentials);
});