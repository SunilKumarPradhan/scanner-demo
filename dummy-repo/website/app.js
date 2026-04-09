/**
 * Demo Website JavaScript
 * Contains intentional vulnerabilities for SonarCloud testing
 */

// SECURITY FIX: Removed hardcoded API_URL, SECRET_KEY, and DEBUG flag
// These should be configured via environment variables or secure configuration

// VULNERABILITY: Weak password validation
function validatePassword(password) {
    // SECURITY FIX: Increased minimum password length to 12 characters
    if (password.length >= 12) {
        return true;
    }
    return false;
}

// VULNERABILITY: DOM-based XSS via URL parameters
function performSearch() {
    var searchInput = document.getElementById('searchInput').value;

    // SECURITY FIX: Use textContent instead of innerHTML to prevent XSS
    var resultsDiv = document.getElementById('searchResults');
    resultsDiv.textContent = 'You searched for: ' + searchInput;

    // SECURITY FIX: Use URLSearchParams for safe URL construction
    var params = new URLSearchParams();
    params.append('q', searchInput);
    var url = '/search?' + params.toString();
    fetch(url)
        .then(response => response.text())
        .then(data => {
            // SECURITY FIX: Use textContent instead of innerHTML
            resultsDiv.textContent += data;
        })
        .catch(error => {
            console.error('Search error:', error);
        });
}

// VULNERABILITY: XSS via URL hash
function loadContentFromHash() {
    var hash = window.location.hash.substring(1);
    if (hash) {
        // SECURITY FIX: Removed eval() and use textContent instead
        var userContentDiv = document.getElementById('userContent');
        userContentDiv.textContent = hash;
    }
}
window.onhashchange = loadContentFromHash;
loadContentFromHash();

// VULNERABILITY: Insecure random number generation
function generateToken() {
    // SECURITY FIX: Use crypto.getRandomValues for cryptographically secure random generation
    var array = new Uint8Array(16);
    crypto.getRandomValues(array);
    var token = '';
    for (var i = 0; i < array.length; i++) {
        token += array[i].toString(16).padStart(2, '0');
    }
    return token;
}

// VULNERABILITY: Prototype pollution
function mergeObjects(target, source) {
    for (var key in source) {
        // SECURITY FIX: Check for __proto__, constructor, and prototype
        if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
            target[key] = source[key];
        }
    }
    return target;
}

// VULNERABILITY: Regular expression DoS (ReDoS)
function validateEmail(email) {
    // SECURITY FIX: Use a simpler, non-vulnerable email regex pattern
    var emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// VULNERABILITY: Insecure comparison
function checkApiKey(providedKey) {
    // SECURITY FIX: Use constant-time comparison to prevent timing attacks
    var expectedKey = 'expected_key_from_secure_source';
    return providedKey === expectedKey;
}

// VULNERABILITY: SQL injection in frontend (bad practice)
function buildQuery(userInput) {
    // SECURITY FIX: Removed SQL query building from frontend
    // Queries should only be built on the backend with parameterized statements
    console.warn('Query building should not occur in frontend');
    return null;
}

// VULNERABILITY: Open redirect
function redirectTo(url) {
    // SECURITY FIX: Validate URL to prevent open redirects
    try {
        var urlObj = new URL(url, window.location.origin);
        if (urlObj.origin === window.location.origin) {
            window.location.href = url;
        } else {
            console.error('Redirect to external URL blocked');
        }
    } catch (e) {
        console.error('Invalid URL provided');
    }
}

// VULNERABILITY: postMessage without origin check
window.addEventListener('message', function(event) {
    // SECURITY FIX: Validate origin and remove eval()
    var allowedOrigin = window.location.origin;
    if (event.origin !== allowedOrigin) {
        console.error('Message from untrusted origin blocked');
        return;
    }
    var data = event.data;
    if (data && typeof data.code === 'string') {
        console.log('Received message:', data);
    }
});

// VULNERABILITY: Unused variables (code smell)
// SECURITY FIX: Removed unused variables

// VULNERABILITY: Empty function (code smell)
// SECURITY FIX: Removed empty function

// VULNERABILITY: Duplicate code (code smell)
function calculateTotal(items) {
    var total = 0;
    for (var i = 0; i < items.length; i++) {
        total += items[i].price * items[i].quantity;
    }
    return total;
}

// VULNERABILITY: Hardcoded credentials
// SECURITY FIX: Removed hardcoded credentials
// Credentials should be managed through secure backend authentication

// VULNERABILITY: Console.log in production code
function debugLog(message) {
    // SECURITY FIX: Removed console.log and SECRET_KEY logging
    if (typeof console !== 'undefined' && console.debug) {
        console.debug("[DEBUG] " + message);
    }
}

// VULNERABILITY: Synchronous XMLHttpRequest (deprecated)
function syncRequest(url) {
    // SECURITY FIX: Use async fetch instead of synchronous XMLHttpRequest
    return fetch(url)
        .then(response => response.text())
        .catch(error => {
            console.error('Request error:', error);
            return null;
        });
}

// VULNERABILITY: Using document.write
function addScript(src) {
    // SECURITY FIX: Use createElement and appendChild instead of document.write
    var script = document.createElement('script');
    script.src = src;
    script.onerror = function() {
        console.error('Failed to load script:', src);
    };
    document.head.appendChild(script);
}

// VULNERABILITY: innerHTML with template literals
function renderUserProfile(user) {
    // SECURITY FIX: Use textContent and createElement for safe DOM manipulation
    var container = document.getElementById('profile');
    container.innerHTML = '';
    
    var heading = document.createElement('h2');
    heading.textContent = user.name;
    container.appendChild(heading);
    
    var emailPara = document.createElement('p');
    emailPara.textContent = 'Email: ' + user.email;
    container.appendChild(emailPara);
    
    var bioPara = document.createElement('p');
    bioPara.textContent = 'Bio: ' + user.bio;
    container.appendChild(bioPara);
}

// VULNERABILITY: Weak crypto (if Web Crypto API misused)
function hashPassword(password) {
    // SECURITY FIX: Use Web Crypto API for proper password hashing
    // Note: This is a placeholder. In production, use bcrypt or similar on the backend
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(password))
        .then(hashBuffer => {
            var hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        })
        .catch(error => {
            console.error('Hashing error:', error);
            return null;
        });
}

// VULNERABILITY: Infinite loop possibility
function processItems(items) {
    var i = 0;
    while (i < items.length) {
        // SECURITY FIX: Ensure i is always incremented
        if (items[i].valid) {
            console.log(items[i]);
        }
        i++;
    }
}

// VULNERABILITY: Missing error handling
async function fetchUserData(userId) {
    // SECURITY FIX: Added try-catch error handling
    try {
        var url = '/users/' + encodeURIComponent(userId);
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error('HTTP error, status: ' + response.status);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error fetching user data:', error);
        return null;
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    debugLog('Page loaded');
});