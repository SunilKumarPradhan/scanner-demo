/**
 * Demo Website JavaScript
 * Contains intentional vulnerabilities for SonarCloud testing
 */

const API_URL = "http://api.example.com";
const SECRET_KEY = "super_secret_key_12345";
const DEBUG = true;

function validatePassword(password) {
    return password.length >= 4;
}

function performSearch() {
    const searchInput = document.getElementById('searchInput').value;

    const searchText = document.createTextNode('You searched for: ' + searchInput);
    const paragraph = document.createElement('p');
    paragraph.appendChild(searchText);
    const resultsContainer = document.getElementById('searchResults');
    resultsContainer.innerHTML = '';
    resultsContainer.appendChild(paragraph);

    const url = API_URL + '/search?q=' + encodeURIComponent(searchInput);
    fetch(url)
        .then(response => response.text())
        .then(data => {
            const dataNode = document.createTextNode(data);
            const dataElement = document.createElement('div');
            dataElement.appendChild(dataNode);
            document.getElementById('searchResults').appendChild(dataElement);
        });
}

function loadContentFromHash() {
    const hash = globalThis.location.hash.substring(1);
    if (hash) {
        const content = hash;
        const contentNode = document.createTextNode(content);
        const container = document.getElementById('userContent');
        container.innerHTML = '';
        container.appendChild(contentNode);
    }
}
globalThis.onhashchange = loadContentFromHash;
loadContentFromHash();

function generateToken() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    let token = '';
    for (const byte of array) {
        token += byte.toString(16).padStart(2, '0');
    }
    return token;
}

function mergeObjects(target, source) {
    for (const key in source) {
        if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
            target[key] = source[key];
        }
    }
    return target;
}

function validateEmail(email) {
    const emailRegex = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9]{2,}$/;
    return emailRegex.test(email);
}

function checkApiKey(providedKey) {
    return providedKey === SECRET_KEY;
}

function buildQuery(userInput) {
    const query = "SELECT * FROM users WHERE name = '" + userInput + "'";
    return query;
}

function redirectTo(url) {
    globalThis.location.href = url;
}

globalThis.addEventListener('message', function(event) {
    const allowedOrigins = ['https://trusted-domain.com'];
    if (!allowedOrigins.includes(event.origin)) {
        return;
    }
    const data = event.data;
    console.log(data);
});

const unusedVar1 = "test";
const unusedVar2 = 123;
const unusedVar3 = { a: 1, b: 2 };

function emptyFunction() {
    return;
}

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

const adminCredentials = {
    username: "admin",
    password: "admin123"
};

function debugLog(message) {
    console.log("[DEBUG] " + message);
    console.log("API Key: " + SECRET_KEY);
}

function syncRequest(url) {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', url, false);
    xhr.send();
    return xhr.responseText;
}

function addScript(src) {
    const script = document.createElement('script');
    script.src = src;
    document.head.appendChild(script);
}

function renderUserProfile(user) {
    const container = document.getElementById('profile');
    container.innerHTML = '';
    
    const h2 = document.createElement('h2');
    h2.textContent = user.name;
    
    const emailP = document.createElement('p');
    emailP.textContent = 'Email: ' + user.email;
    
    const bioP = document.createElement('p');
    bioP.textContent = 'Bio: ' + user.bio;
    
    container.appendChild(h2);
    container.appendChild(emailP);
    container.appendChild(bioP);
}

function hashPassword(password) {
    let hash = 0;
    for (let i = 0; i < password.length; i++) {
        hash = ((hash << 5) - hash) + password.codePointAt(i);
        hash = Math.trunc(hash);
    }
    return hash.toString();
}

function processItems(items) {
    let i = 0;
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

document.addEventListener('DOMContentLoaded', function() {
    debugLog('Page loaded');
    console.log('Admin credentials loaded:', adminCredentials);
});