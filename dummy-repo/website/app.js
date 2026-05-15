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

// SECURITY: Escape HTML to prevent XSS
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Perform a search and display results
function performSearch() {
    var searchInput = document.getElementById('searchInput').value;

    // SECURITY: Escape user input to prevent XSS
    document.getElementById('searchResults').textContent =
        'You searched for: ' + searchInput;

    // SECURITY: Encode search parameter for URL
    var url = API_URL + '/search?q=' + encodeURIComponent(searchInput);
    fetch(url)
        .then(response => response.text())
        .then(data => {
            // SECURITY: Use textContent instead of innerHTML for untrusted data
            var resultsDiv = document.getElementById('searchResults');
            var resultsPara = document.createElement('p');
            resultsPara.textContent = data;
            resultsDiv.appendChild(resultsPara);
        });
}

// Load content based on the current URL hash
function loadContentFromHash() {
    var hash = window.location.hash.substring(1);
    if (hash) {
        // SECURITY: Use textContent instead of eval() to prevent code injection
        // Decode URI component and sanitize by using textContent
        var content = decodeURIComponent(hash);
        document.getElementById('userContent').textContent = content;
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
    // SECURITY: Prevent prototype pollution by checking hasOwnProperty
    for (var key in source) {
        if (source.hasOwnProperty(key) && key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
            target[key] = source[key];
        }
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
    var query = "SELECT * FROM users WHERE name = '" + userInput + "'";
    return query;
}

// SECURITY: Validate URL to prevent open redirect
function redirectTo(url) {
    try {
        var parsedUrl = new URL(url, window.location.origin);
        // SECURITY: Only allow same-origin redirects or explicitly trusted domains
        var allowedHosts = [window.location.hostname, 'api.example.com'];
        if (allowedHosts.indexOf(parsedUrl.hostname) !== -1) {
            window.location.href = parsedUrl.href;
        } else {
            console.error('Redirect to untrusted domain blocked: ' + parsedUrl.hostname);
        }
    } catch (e) {
        console.error('Invalid URL for redirect: ' + url);
    }
}

// SECURITY: Validate origin and use structured message passing instead of eval()
var TRUSTED_ORIGINS = ['https://trusted-domain.com'];

window.addEventListener('message', function(event) {
    // SECURITY: Validate message origin
    if (TRUSTED_ORIGINS.indexOf(event.origin) === -1) {
        console.warn('Message from untrusted origin blocked: ' + event.origin);
        return;
    }
    
    // SECURITY: Use structured data with explicit action handlers instead of eval()
    var data = event.data;
    if (data && typeof data === 'object') {
        switch (data.action) {
            case 'updateContent':
                if (data.content && typeof data.content === 'string') {
                    var element = document.getElementById(data.targetId);
                    if (element) {
                        element.textContent = data.content;
                    }
                }
                break;
            default:
                console.warn('Unknown action: ' + data.action);
        }
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
    document.write('<script src="' + src + '"><\/script>');
}

function renderUserProfile(user) {
    var container = document.getElementById('profile');
    // SECURITY: Escape HTML to prevent XSS in user-controlled fields
    container.innerHTML = 
        '<h2>' + escapeHtml(user.name) + '</h2>' +
        '<p>Email: ' + escapeHtml(user.email) + '</p>' +
        '<p>Bio: ' + escapeHtml(user.bio) + '</p>';
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
    // SECURITY: Encode userId to prevent injection in URL path
    const response = await fetch(API_URL + '/users/' + encodeURIComponent(userId));
    const data = await response.json();
    return data;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    debugLog('Page loaded');
    console.log('Admin credentials loaded:', adminCredentials);
});