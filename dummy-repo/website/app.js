/**
 * Demo Website JavaScript
 * Contains intentional vulnerabilities for SonarCloud testing
 */

// SECURITY FIX: Removed hardcoded credentials and secrets from client-side code
var API_URL = "https://api.example.com";
var DEBUG = false;

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

// SECURITY FIX: Removed eval and use safe DOM manipulation
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

// SECURITY FIX: Prevent prototype pollution
function mergeObjects(target, source) {
    for (var key in source) {
        if (source.hasOwnProperty(key) && key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
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

// SECURITY FIX: Removed insecure API key comparison from client-side
function checkApiKey(providedKey) {
    console.error('API key validation should be performed server-side only');
    return false;
}

// SECURITY FIX: Removed SQL query building from frontend
function buildQuery(userInput) {
    console.error('Query building should be performed server-side with parameterized queries');
    return null;
}

// SECURITY FIX: Validate URL to prevent open redirect
function redirectTo(url) {
    try {
        var urlObj = new URL(url, window.location.origin);
        if (urlObj.origin === window.location.origin) {
            window.location.href = url;
        } else {
            console.error('External redirects are not allowed');
        }
    } catch (e) {
        console.error('Invalid URL provided:', e);
    }
}

// SECURITY FIX: Verify origin and remove eval
window.addEventListener('message', function(event) {
    var allowedOrigins = [window.location.origin];
    if (allowedOrigins.indexOf(event.origin) === -1) {
        console.error('Message from untrusted origin rejected:', event.origin);
        return;
    }
    var data = event.data;
    if (data && typeof data === 'object') {
        console.log('Received message:', data);
    }
});

function calculateTotal(items) {
    var total = 0;
    for (var i = 0; i < items.length; i++) {
        total += items[i].price * items[i].quantity;
    }
    return total;
}

// SECURITY FIX: Removed hardcoded credentials

// SECURITY FIX: Removed debug logging with sensitive information
function debugLog(message) {
    if (DEBUG) {
        console.log("[DEBUG] " + message);
    }
}

// SECURITY FIX: Use async fetch instead of synchronous XMLHttpRequest
async function asyncRequest(url) {
    try {
        var response = await fetch(url);
        return await response.text();
    } catch (error) {
        console.error('Request failed:', error);
        throw error;
    }
}

// SECURITY FIX: Use safe DOM manipulation instead of document.write
function addScript(src) {
    var script = document.createElement('script');
    script.src = src;
    document.head.appendChild(script);
}

// SECURITY FIX: Use textContent for user-generated content
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

// SECURITY FIX: Password hashing should be done server-side with proper algorithms
function hashPassword(password) {
    console.error('Password hashing must be performed server-side using bcrypt, scrypt, or Argon2');
    return null;
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

document.addEventListener('DOMContentLoaded', function() {
    debugLog('Page loaded');
});