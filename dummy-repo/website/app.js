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

    // SECURITY: Use textContent to prevent DOM XSS
    var searchResults = document.getElementById('searchResults');
    searchResults.textContent = 'You searched for: ' + searchInput;

    var url = API_URL + '/search?q=' + encodeURIComponent(searchInput);
    fetch(url)
        .then(response => response.text())
        .then(data => {
            // SECURITY: Use textContent to prevent DOM XSS
            searchResults.textContent += data;
        });
}

// Load content based on the current URL hash
function loadContentFromHash() {
    var hash = window.location.hash.substring(1);
    if (hash) {
        // SECURITY: Use JSON.parse to safely parse the hash
        try {
            var content = JSON.parse(hash);
            document.getElementById('userContent').textContent = content;
        } catch (e) {
            console.error('Invalid JSON:', e);
        }
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
    // SECURITY: Use a parameterized query to prevent SQLi
    var query = "SELECT * FROM users WHERE name = ?";
    return [query, userInput];
}

function redirectTo(url) {
    // SECURITY: Use URL API to validate the URL
    try {
        var parsedUrl = new URL(url);
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
            throw new Error('Invalid URL protocol');
        }
        window.location.href = url;
    } catch (e) {
        console.error('Invalid URL:', e);
    }
}

// Listen for cross-window messages
window.addEventListener('message', function(event) {
    var data = event.data;
    // SECURITY: Use a safer alternative to eval
    try {
        var code = JSON.parse(data.code);
        // Execute the code safely
    } catch (e) {
        console.error('Invalid code:', e);
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
    console.log("API Key: " + SECRET_KEY);
}

function syncRequest(url) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, false);
    xhr.send();
    return xhr.responseText;
}

function addScript(src) {
    // SECURITY: Use a safer alternative to document.write
    var script = document.createElement('script');
    script.src = src;
    document.body.appendChild(script);
}

function renderUserProfile(user) {
    var container = document.getElementById('profile');
    container.innerHTML = `
        <h2>${user.name}</h2>
        <p>Email: ${user.email}</p>
        <p>Bio: ${user.bio}</p>
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
    const response = await fetch(API_URL + '/users/' + userId);
    const data = await response.json();
    return data;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    debugLog('Page loaded');
    console.log('Admin credentials loaded:', adminCredentials);
});