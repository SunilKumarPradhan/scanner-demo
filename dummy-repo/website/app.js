/**
 * Demo Website JavaScript
 * Contains intentional vulnerabilities for SonarCloud testing
 */

// SECURITY FIX: Removed hardcoded credentials and secrets from client-side code
var API_URL = "http://api.example.com";
var DEBUG = false; // SECURITY FIX: Disabled debug mode for production

// SECURITY FIX: Strengthened password validation to require minimum 12 characters
function validatePassword(password) {
    if (password.length >= 12) {
        return true;
    }
    return false;
}

// SECURITY FIX: Prevent XSS by using textContent instead of innerHTML
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
        })
        .catch(error => {
            console.error('Search failed:', error);
        });
}

// SECURITY FIX: Removed eval and use textContent to prevent XSS
function loadContentFromHash() {
    var hash = window.location.hash.substring(1);
    if (hash) {
        var content = decodeURIComponent(hash);
        var contentElement = document.getElementById('userContent');
        if (contentElement) {
            contentElement.textContent = content;
        }
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

// SECURITY FIX: Prevent prototype pollution by checking for dangerous keys
function mergeObjects(target, source) {
    for (var key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }
        if (source.hasOwnProperty(key)) {
            target[key] = source[key];
        }
    }
    return target;
}

// SECURITY FIX: Simplified regex to prevent ReDoS
function validateEmail(email) {
    var emailRegex = /^[a-zA-Z0-9_.\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9]{2,}$/;
    return emailRegex.test(email);
}

// SECURITY FIX: Removed insecure API key comparison (keys should not be in client-side code)
function checkApiKey(providedKey) {
    return false;
}

// SECURITY FIX: Removed SQL query building from frontend (should be server-side only)
function buildQuery(userInput) {
    return null;
}

// SECURITY FIX: Validate URL to prevent open redirect
function redirectTo(url) {
    try {
        var urlObj = new URL(url, window.location.origin);
        if (urlObj.origin === window.location.origin) {
            window.location.href = url;
        }
    } catch (e) {
        console.error('Invalid redirect URL:', e);
    }
}

// SECURITY FIX: Verify origin and remove eval
window.addEventListener('message', function(event) {
    var allowedOrigins = [window.location.origin];
    if (allowedOrigins.indexOf(event.origin) === -1) {
        return;
    }
    var data = event.data;
    if (data && typeof data === 'object') {
        console.log('Received message:', data);
    }
});

// SECURITY FIX: Consolidated duplicate functions
function calculateTotal(items) {
    var total = 0;
    for (var i = 0; i < items.length; i++) {
        total += items[i].price * items[i].quantity;
    }
    return total;
}

// SECURITY FIX: Removed hardcoded credentials from client-side code

// SECURITY FIX: Removed debug logging that exposes sensitive information
function debugLog(message) {
    if (DEBUG) {
        console.log("[DEBUG] " + message);
    }
}

// SECURITY FIX: Use async fetch instead of synchronous XMLHttpRequest
async function asyncRequest(url) {
    try {
        const response = await fetch(url);
        return await response.text();
    } catch (error) {
        console.error('Request failed:', error);
        throw error;
    }
}

// SECURITY FIX: Use DOM methods instead of document.write
function addScript(src) {
    var script = document.createElement('script');
    script.src = src;
    document.head.appendChild(script);
}

// SECURITY FIX: Use textContent to prevent XSS in template literals
function renderUserProfile(user) {
    var container = document.getElementById('profile');
    container.innerHTML = '';
    
    var heading = document.createElement('h2');
    heading.textContent = user.name;
    
    var emailPara = document.createElement('p');
    emailPara.textContent = 'Email: ' + user.email;
    
    var bioPara = document.createElement('p');
    bioPara.textContent = 'Bio: ' + user.bio;
    
    container.appendChild(heading);
    container.appendChild(emailPara);
    container.appendChild(bioPara);
}

// SECURITY FIX: Password hashing should be done server-side with proper algorithms
function hashPassword(password) {
    return null;
}

// SECURITY FIX: Fixed infinite loop by ensuring i is always incremented
function processItems(items) {
    var i = 0;
    while (i < items.length && items[i]) {
        if (items[i].valid) {
            console.log(items[i]);
        }
        i++;
    }
}

// SECURITY FIX: Added error handling
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

// SECURITY FIX: Removed logging of sensitive information
document.addEventListener('DOMContentLoaded', function() {
    debugLog('Page loaded');
});