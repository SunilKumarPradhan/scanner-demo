/**
 * Demo Website JavaScript
 * Contains intentional vulnerabilities for SonarCloud testing
 */

// SECURITY FIX: Removed hardcoded credentials and secrets from client-side code
var API_URL = "http://api.example.com";
var DEBUG = false; // SECURITY FIX: Disabled debug mode for production

// VULNERABILITY: Weak password validation
function validatePassword(password) {
    // BUG: Password only requires 4 characters
    if (password.length >= 4) {
        return true;
    }
    return false;
}

// SECURITY FIX: Use textContent instead of innerHTML to prevent XSS
function performSearch() {
    var searchInput = document.getElementById('searchInput').value;

    var resultsElement = document.getElementById('searchResults');
    var searchText = document.createElement('p');
    searchText.textContent = 'You searched for: ' + searchInput;
    resultsElement.innerHTML = '';
    resultsElement.appendChild(searchText);

    var url = API_URL + '/search?q=' + encodeURIComponent(searchInput);
    fetch(url)
        .then(response => response.text())
        .then(data => {
            var dataElement = document.createElement('div');
            dataElement.textContent = data;
            resultsElement.appendChild(dataElement);
        });
}

// SECURITY FIX: Removed eval and use textContent instead of innerHTML
function loadContentFromHash() {
    var hash = window.location.hash.substring(1);
    if (hash) {
        var content = decodeURIComponent(hash);
        var contentElement = document.getElementById('userContent');
        contentElement.textContent = content;
    }
}
window.onhashchange = loadContentFromHash;
loadContentFromHash();

// SECURITY FIX: Use crypto.getRandomValues for cryptographically secure random tokens
function generateToken() {
    var array = new Uint8Array(16);
    crypto.getRandomValues(array);
    var token = '';
    for (var i = 0; i < array.length; i++) {
        token += ('0' + array[i].toString(16)).slice(-2);
    }
    return token;
}

// SECURITY FIX: Prevent prototype pollution
function mergeObjects(target, source) {
    for (var key in source) {
        if (source.hasOwnProperty(key) && key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
            target[key] = source[key];
        }
    }
    return target;
}

// VULNERABILITY: Regular expression DoS (ReDoS)
function validateEmail(email) {
    // BUG: Vulnerable regex pattern
    var emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,})+$/;
    return emailRegex.test(email);
}

// SECURITY FIX: Removed insecure comparison function - secrets should not be in client-side code
function checkApiKey(providedKey) {
    return false;
}

// VULNERABILITY: SQL injection in frontend (bad practice)
function buildQuery(userInput) {
    // CODE SMELL: Building query strings in frontend
    var query = "SELECT * FROM users WHERE name = '" + userInput + "'";
    return query;
}

// SECURITY FIX: Validate URL to prevent open redirect
function redirectTo(url) {
    try {
        var urlObj = new URL(url, window.location.origin);
        if (urlObj.origin === window.location.origin) {
            window.location.href = url;
        }
    } catch (e) {
        console.error('Invalid URL');
    }
}

// SECURITY FIX: Verify origin and remove eval
window.addEventListener('message', function(event) {
    if (event.origin !== window.location.origin) {
        return;
    }
    var data = event.data;
    if (data && typeof data === 'object') {
        console.log('Received message:', data);
    }
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

// SECURITY FIX: Removed hardcoded credentials from client-side code

// SECURITY FIX: Removed debug logging that exposes secrets
function debugLog(message) {
    if (DEBUG) {
        console.log("[DEBUG] " + message);
    }
}

// VULNERABILITY: Synchronous XMLHttpRequest (deprecated)
function syncRequest(url) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, false);
    xhr.send();
    return xhr.responseText;
}

// SECURITY FIX: Use DOM methods instead of document.write
function addScript(src) {
    var script = document.createElement('script');
    script.src = src;
    document.head.appendChild(script);
}

// SECURITY FIX: Use textContent for user-controlled data
function renderUserProfile(user) {
    var container = document.getElementById('profile');
    container.innerHTML = '';
    
    var nameHeader = document.createElement('h2');
    nameHeader.textContent = user.name;
    
    var emailPara = document.createElement('p');
    emailPara.textContent = 'Email: ' + user.email;
    
    var bioPara = document.createElement('p');
    bioPara.textContent = 'Bio: ' + user.bio;
    
    container.appendChild(nameHeader);
    container.appendChild(emailPara);
    container.appendChild(bioPara);
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

// SECURITY FIX: Removed logging of sensitive credentials
document.addEventListener('DOMContentLoaded', function() {
    debugLog('Page loaded');
});