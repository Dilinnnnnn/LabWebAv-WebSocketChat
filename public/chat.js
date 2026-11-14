// ============================================
// CONFIGURACIÓN
// ============================================
const MAX_MESSAGE_LENGTH = 500;
const RECONNECT_DELAY = 3000;
const TYPING_TIMEOUT = 3000;

// ============================================
// ELEMENTOS DEL DOM - Login/Auth
// ============================================
const loginScreen = document.getElementById('login-screen');
const chatScreen = document.getElementById('chat-screen');
const tabLogin = document.getElementById('tab-login');
const tabRegister = document.getElementById('tab-register');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const loginUsername = document.getElementById('login-username');
const loginPassword = document.getElementById('login-password');
const registerUsername = document.getElementById('register-username');
const registerPassword = document.getElementById('register-password');
const loginError = document.getElementById('login-error');
const registerError = document.getElementById('register-error');
const logoutBtn = document.getElementById('logout-btn');

// ============================================
// ELEMENTOS DEL DOM - Chat
// ============================================
const messageInput = document.getElementById('messageInput');
const sendBtn = document.getElementById('sendBtn');
const messagesArea = document.getElementById('messages');
const connectionStatus = document.getElementById('connection-status');
const userCountEl = document.getElementById('user-count');
const themeToggle = document.getElementById('theme-toggle');
const typingIndicator = document.getElementById('typing-indicator');
const typingText = document.getElementById('typing-text');

// ============================================
// ESTADO GLOBAL
// ============================================
let ws = null;
let username = '';
let jwtToken = '';
let isConnected = false;
let isJoined = false;
let typingTimer = null;
let isTyping = false;
let typingUsers = new Set();

// ============================================
// TEMA CLARO/OSCURO - Persistencia con localStorage
// ============================================
function initTheme() {
    const savedTheme = localStorage.getItem('chat-theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('chat-theme', next);
}

themeToggle.addEventListener('click', toggleTheme);

// ============================================
// AUTENTICACIÓN JWT - Registro y Login
// ============================================

// Toggle entre pestañas de login y registro
tabLogin.addEventListener('click', () => switchAuthTab('login'));
tabRegister.addEventListener('click', () => switchAuthTab('register'));

function switchAuthTab(mode) {
    if (mode === 'login') {
        tabLogin.classList.add('active');
        tabRegister.classList.remove('active');
        loginForm.classList.add('active');
        registerForm.classList.remove('active');
    } else {
        tabRegister.classList.add('active');
        tabLogin.classList.remove('active');
        registerForm.classList.add('active');
        loginForm.classList.remove('active');
    }
    loginError.classList.add('hidden');
    registerError.classList.add('hidden');
}

// Registro de usuario
registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    registerError.classList.add('hidden');

    const uname = registerUsername.value.trim();
    const pass = registerPassword.value;

    if (uname.length < 3) {
        showAuthError(registerError, 'El usuario debe tener al menos 3 caracteres');
        return;
    }
    if (pass.length < 6) {
        showAuthError(registerError, 'La contraseña debe tener al menos 6 caracteres');
        return;
    }

    try {
        const res = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: uname, password: pass })
        });
        const data = await res.json();

        if (res.ok) {
            // Auto-login después del registro
            registerUsername.value = '';
            registerPassword.value = '';
            loginUsername.value = uname;
            loginPassword.value = pass;
            switchAuthTab('login');
            showAuthError(loginError, 'Cuenta creada. Inicia sesión.', false);
        } else {
            showAuthError(registerError, data.error || 'Error al registrar');
        }
    } catch (err) {
        showAuthError(registerError, 'Error de conexión con el servidor');
    }
});

// Login de usuario
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginError.classList.add('hidden');

    const uname = loginUsername.value.trim();
    const pass = loginPassword.value;

    if (!uname || !pass) {
        showAuthError(loginError, 'Completa todos los campos');
        return;
    }

    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: uname, password: pass })
        });
        const data = await res.json();

        if (res.ok && data.success) {
            // Guardar JWT en localStorage (persistencia de sesión)
            jwtToken = data.token;
            username = data.username;
            localStorage.setItem('chat-jwt', jwtToken);
            localStorage.setItem('chat-username', username);

            // Ir al chat
            showChatScreen();
        } else {
            showAuthError(loginError, data.error || 'Error al iniciar sesión');
        }
    } catch (err) {
        showAuthError(loginError, 'Error de conexión con el servidor');
    }
});

function showAuthError(el, msg, isError = true) {
    el.textContent = msg;
    el.classList.remove('hidden');
    el.style.color = isError ? 'var(--color-error)' : 'var(--color-acento)';
}

// Logout
logoutBtn.addEventListener('click', () => {
    localStorage.removeItem('chat-jwt');
    localStorage.removeItem('chat-username');
    jwtToken = '';
    username = '';
    isJoined = false;
    if (ws) ws.close();
    chatScreen.classList.add('hidden');
    loginScreen.classList.remove('hidden');
    loginUsername.value = '';
    loginPassword.value = '';
    loginUsername.focus();
});

// Mostrar pantalla del chat
function showChatScreen() {
    loginScreen.classList.add('hidden');
    chatScreen.classList.remove('hidden');
    connectWebSocket();
}

// ============================================
// CONEXIÓN WEBSOCKET CON JWT
// ============================================
function connectWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Pasar el token JWT como query parameter para autenticación
    const wsUrl = `${protocol}//${location.host}?token=${encodeURIComponent(jwtToken)}`;

    updateStatus('reconectando');
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        isConnected = true;
        updateStatus('conectado');
        sendBtn.disabled = false;
        messageInput.disabled = false;
        messageInput.focus();
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleMessage(data);
        } catch (err) {
            console.error('Error parseando mensaje:', err);
        }
    };

    ws.onclose = (event) => {
        isConnected = false;
        updateStatus('desconectado');
        sendBtn.disabled = true;
        messageInput.disabled = true;

        // Si fue cerrado por auth (código 4001-4003), volver al login
        if (event.code >= 4001 && event.code <= 4003) {
            localStorage.removeItem('chat-jwt');
            localStorage.removeItem('chat-username');
            jwtToken = '';
            chatScreen.classList.add('hidden');
            loginScreen.classList.remove('hidden');
            showAuthError(loginError, 'Sesión expirada. Inicia sesión nuevamente.');
            return;
        }

        // Reconexión automática
        if (jwtToken) {
            updateStatus('reconectando');
            setTimeout(connectWebSocket, RECONNECT_DELAY);
        }
    };

    ws.onerror = (error) => {
        console.error('Error WebSocket:', error);
    };
}

// ============================================
// MANEJO DE MENSAJES ENTRANTE
// ============================================
function handleMessage(data) {
    switch (data.type) {
        case 'message':
            addMessage(data.username, data.text, data.timestamp, data.username === username);
            removeTypingUser(data.username);
            break;

        case 'history':
            // Cargar historial de mensajes guardados en Firestore
            if (data.messages && data.messages.length > 0) {
                messagesArea.innerHTML = '';
                data.messages.forEach(msg => {
                    addMessage(msg.username, msg.text, msg.timestamp, msg.username === username);
                });
            }
            break;

        case 'system':
            addSystemMessage(data);
            break;

        case 'userCount':
            updateUserCount(data.count);
            break;

        case 'typing':
            handleTyping(data);
            break;

        case 'error':
            addErrorMessage(data.text);
            break;

        default:
            break;
    }
}

// ============================================
// RENDERIZAR MENSAJES
// ============================================
function addMessage(sender, text, timestamp, isOwn = false) {
    const bubble = document.createElement('div');
    bubble.className = `message-bubble ${isOwn ? 'message-sent' : 'message-received'}`;

    const safeSender = escapeHtml(sender);
    const safeText = escapeHtml(text);
    const safeTime = escapeHtml(timestamp);

    bubble.innerHTML = `
        ${!isOwn ? `<div class="message-sender">${safeSender}</div>` : ''}
        <div class="message-text">${safeText}</div>
        <span class="message-time">${safeTime}</span>
    `;

    messagesArea.appendChild(bubble);
    scrollToBottom();
}

function addSystemMessage(data) {
    const sysMsg = document.createElement('div');
    sysMsg.className = 'message-system';

    const action = data.event === 'join' ? 'se unió' : 'salió';
    sysMsg.textContent = `${data.username} ${action} al chat`;

    messagesArea.appendChild(sysMsg);
    scrollToBottom();
}

function addErrorMessage(text) {
    const errMsg = document.createElement('div');
    errMsg.className = 'message-error';
    errMsg.textContent = text;
    messagesArea.appendChild(errMsg);
    scrollToBottom();

    setTimeout(() => {
        if (errMsg.parentNode) errMsg.remove();
    }, 4000);
}

// ============================================
// CONTADOR Y ESTADO
// ============================================
function updateUserCount(count) {
    userCountEl.textContent = count === 1 ? '1 usuario' : `${count} usuarios`;
}

function updateStatus(status) {
    connectionStatus.className = `status-indicator status-${status}`;
    const textEl = connectionStatus.querySelector('.status-text');
    const labels = {
        conectado: 'Conectado',
        desconectado: 'Desconectado',
        reconectando: 'Reconectando...'
    };
    textEl.textContent = labels[status] || status;
}

// ============================================
// INDICADOR "ESCRIBIENDO..."
// ============================================
function handleTyping(data) {
    if (data.username === username) return;

    if (data.isTyping) {
        typingUsers.add(data.username);
    } else {
        typingUsers.delete(data.username);
    }
    updateTypingDisplay();
}

function updateTypingDisplay() {
    if (typingUsers.size === 0) {
        typingIndicator.classList.add('hidden');
    } else {
        typingIndicator.classList.remove('hidden');
        const users = Array.from(typingUsers);
        if (users.length === 1) {
            typingText.textContent = `${users[0]} está escribiendo...`;
        } else if (users.length === 2) {
            typingText.textContent = `${users[0]} y ${users[1]} están escribiendo...`;
        } else {
            typingText.textContent = `${users[0]} y ${typingUsers.size - 1} más están escribiendo...`;
        }
    }
}

function removeTypingUser(user) {
    typingUsers.delete(user);
    updateTypingDisplay();
}

function sendTypingStatus(typing) {
    if (!isConnected) return;
    sendMessage({ type: 'typing', username: username, isTyping: typing });
}

messageInput.addEventListener('input', () => {
    if (!isConnected) return;

    if (!isTyping) {
        isTyping = true;
        sendTypingStatus(true);
    }

    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => {
        isTyping = false;
        sendTypingStatus(false);
    }, TYPING_TIMEOUT);
});

// ============================================
// ENVÍO DE MENSAJES
// ============================================
function sendMessage(data) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify(data));
}

function sendChatMessage() {
    const text = messageInput.value.trim();

    if (!text) return;

    if (text.length > MAX_MESSAGE_LENGTH) {
        addErrorMessage(`El mensaje excede el máximo de ${MAX_MESSAGE_LENGTH} caracteres`);
        return;
    }

    if (!isConnected) {
        addErrorMessage('No hay conexión al servidor');
        return;
    }

    sendMessage({ type: 'message', text: text });

    messageInput.value = '';
    isTyping = false;
    sendTypingStatus(false);
}

// ============================================
// EVENT LISTENERS
// ============================================
sendBtn.addEventListener('click', sendChatMessage);

messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendChatMessage();
    }
});

// ============================================
// UTILIDADES
// ============================================
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function scrollToBottom() {
    messagesArea.scrollTop = messagesArea.scrollHeight;
}

// ============================================
// INICIALIZACIÓN
// ============================================
initTheme();

// Verificar si hay un token JWT guardado (recordar sesión)
const savedToken = localStorage.getItem('chat-jwt');
const savedUsername = localStorage.getItem('chat-username');

if (savedToken && savedUsername) {
    // Intentar reconectar con el token guardado
    jwtToken = savedToken;
    username = savedUsername;
    // Verificar token con el servidor antes de mostrar el chat
    fetch('/api/messages', {
        headers: { 'Authorization': `Bearer ${jwtToken}` }
    }).then(res => {
        if (res.ok) {
            showChatScreen();
        } else {
            // Token expirado, limpiar y mostrar login
            localStorage.removeItem('chat-jwt');
            localStorage.removeItem('chat-username');
            loginUsername.focus();
        }
    }).catch(() => {
        loginUsername.focus();
    });
} else {
    loginUsername.focus();
}
