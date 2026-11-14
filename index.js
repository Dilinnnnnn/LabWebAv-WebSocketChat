require('dotenv').config();

const express = require('express');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');

const fb = require('./firebase-config');

const app = express();
app.use(express.json());

// ============================================
// VARIABLES DE ENTORNO (leídas desde .env)
// ============================================
const port = parseInt(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_change_me';
const JWT_EXPIRES_IN = parseInt(process.env.JWT_EXPIRES_IN) || 3600;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
const MAX_MESSAGE_LENGTH = parseInt(process.env.MAX_MESSAGE_LENGTH) || 500;
const MAX_USERNAME_LENGTH = parseInt(process.env.MAX_USERNAME_LENGTH) || 20;

// ============================================
// INICIALIZAR FIREBASE
// ============================================
const { auth: firebaseAuth, firestore } = fb.initializeFirebase();
const FIREBASE_ENABLED = !!(firebaseAuth && firestore);

// ============================================
// AUTENTICACIÓN CON FIREBASE AUTHENTICATION + JWT
// ============================================

// Registrar usuario en Firebase Authentication
app.post('/api/register', async (req, res) => {
    try {
        const username = (req.body.username || '').trim().slice(0, MAX_USERNAME_LENGTH);
        const password = req.body.password || '';

        if (!username || username.length < 3) {
            return res.status(400).json({ error: 'Usuario debe tener al menos 3 caracteres' });
        }
        if (!password || password.length < 6) {
            return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
        }

        if (!FIREBASE_ENABLED) {
            return res.status(503).json({
                error: 'Firebase no está configurado. Verifica el Service Account JSON.'
            });
        }

        // Crear usuario en Firebase Authentication
        const result = await fb.createFirebaseUser(username, password);

        if (!result.success) {
            return res.status(409).json({ error: result.error });
        }

        // Guardar el hash del password en Firestore para verificación posterior
        await fb.saveUserPasswordHash(result.uid, password);

        console.log(`Usuario registrado en Firebase Auth: ${username} (${result.uid})`);
        res.status(201).json({
            success: true,
            uid: result.uid,
            message: 'Usuario registrado correctamente en Firebase Authentication'
        });
    } catch (err) {
        console.error('Error en registro:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Login: validar credenciales en Firebase y generar JWT
app.post('/api/login', async (req, res) => {
    try {
        const username = (req.body.username || '').trim();
        const password = req.body.password || '';

        if (!username || !password) {
            return res.status(400).json({ error: 'Completa todos los campos' });
        }

        if (!FIREBASE_ENABLED) {
            return res.status(503).json({
                error: 'Firebase no está configurado. Verifica el Service Account JSON.'
            });
        }

        // Verificar credenciales contra Firebase Auth + Firestore
        const result = await fb.verifyFirebaseUser(username, password);

        if (!result.success) {
            console.log(`Login fallido: ${username}`);
            return res.status(401).json({ error: result.error });
        }

        // Generar token JWT
        const token = jwt.sign(
            { username: username, uid: result.uid },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );

        console.log(`Login exitoso (Firebase Auth): ${username} (${result.uid})`);
        res.json({
            success: true,
            token: token,
            username: username,
            uid: result.uid,
            expiresIn: JWT_EXPIRES_IN
        });
    } catch (err) {
        console.error('Error en login:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Obtener historial de mensajes (requiere JWT)
app.get('/api/messages', authenticateToken, async (req, res) => {
    const messages = await fb.getMessagesFromFirestore(50);
    res.json({ messages });
});

// Middleware: verificar JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token no proporcionado' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido o expirado' });
        }
        req.user = decoded;
        next();
    });
}

// Servir archivos estáticos
app.use(express.static('public'));

// ============================================
// VALIDACIÓN DE DOMINIO PARA WEBSOCKET
// ============================================
function isOriginAllowed(origin) {
    if (ALLOWED_ORIGINS.includes('*')) return true;
    if (!origin) return true;

    try {
        const url = new URL(origin);
        const hostname = url.hostname;

        return ALLOWED_ORIGINS.some(allowed => {
            if (allowed === hostname) return true;
            if (hostname.endsWith('.' + allowed)) return true;
            return false;
        });
    } catch {
        return false;
    }
}

// ============================================
// CREAR SERVIDOR HTTP
// ============================================
const server = app.listen(port, () => {
    console.log(`========================================`);
    console.log(`  Servidor corriendo en http://localhost:${port}`);
    console.log(`  Orígenes permitidos: ${ALLOWED_ORIGINS.join(', ')}`);
    console.log(`  JWT expira en: ${JWT_EXPIRES_IN}s`);
    console.log(`  Variables de entorno: cargadas desde .env`);
    console.log(`  Firebase Authentication: ${FIREBASE_ENABLED ? 'ACTIVO' : 'NO CONFIGURADO'}`);
    console.log(`  Firestore Database:      ${FIREBASE_ENABLED ? 'ACTIVO' : 'NO CONFIGURADO'}`);
    console.log(`========================================`);
});

// ============================================
// SERVIDOR WEBSOCKET CON JWT + VALIDACIÓN DE DOMINIO
// ============================================
const wss = new WebSocket.Server({ server });

const clients = new Map();

function broadcast(data, exclude = null) {
    const payload = JSON.stringify(data);
    clients.forEach((meta, client) => {
        if (client !== exclude && client.readyState === WebSocket.OPEN) {
            client.send(payload);
        }
    });
}

function broadcastUserCount() {
    broadcast({ type: 'userCount', count: clients.size });
}

wss.on('connection', async (ws, req) => {
    // VALIDACIÓN DE DOMINIO
    const origin = req.headers.origin;
    if (!isOriginAllowed(origin)) {
        console.log(`Conexión rechazada - dominio no permitido: ${origin}`);
        ws.send(JSON.stringify({
            type: 'error',
            text: 'Acceso denegado: dominio no autorizado'
        }));
        ws.close(4001, 'Origin not allowed');
        return;
    }

    // AUTENTICACIÓN JWT EN WEBSOCKET
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');

    let authenticatedUser = null;

    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            authenticatedUser = decoded.username;
        } catch (err) {
            console.log('WebSocket: token JWT inválido');
            ws.send(JSON.stringify({
                type: 'error',
                text: 'Token de autenticación inválido o expirado'
            }));
            ws.close(4002, 'Invalid token');
            return;
        }
    } else {
        ws.send(JSON.stringify({
            type: 'error',
            text: 'Se requiere autenticación JWT para conectarse'
        }));
        ws.close(4003, 'No token provided');
        return;
    }

    clients.set(ws, { username: authenticatedUser, token });
    console.log(`Cliente autenticado: ${authenticatedUser}. Total: ${clients.size}`);

    broadcast({
        type: 'system',
        event: 'join',
        username: authenticatedUser,
        timestamp: new Date().toLocaleTimeString('es-ES', { hour12: false })
    });

    broadcastUserCount();

    // Enviar historial de mensajes desde Firestore
    const history = await fb.getMessagesFromFirestore(50);
    if (history.length > 0) {
        ws.send(JSON.stringify({ type: 'history', messages: history }));
    }

    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data.toString());
            const meta = clients.get(ws);
            const currentUser = meta ? meta.username : 'Anonimo';

            switch (message.type) {
                case 'message': {
                    const text = (message.text || '').trim();

                    if (!text) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            text: 'El mensaje no puede estar vacío'
                        }));
                        return;
                    }

                    if (text.length > MAX_MESSAGE_LENGTH) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            text: `El mensaje excede el máximo de ${MAX_MESSAGE_LENGTH} caracteres`
                        }));
                        return;
                    }

                    const timestamp = new Date().toLocaleTimeString('es-ES', { hour12: false });

                    const msgData = {
                        type: 'message',
                        username: currentUser,
                        text: text,
                        timestamp: timestamp
                    };

                    // Guardar mensaje en Firestore (base de datos real)
                    fb.saveMessageToFirestore(currentUser, text, timestamp)
                        .catch(err => console.error('Error guardando en Firestore:', err));

                    broadcast(msgData);
                    break;
                }

                case 'typing': {
                    broadcast({
                        type: 'typing',
                        username: currentUser,
                        isTyping: message.isTyping
                    }, ws);
                    break;
                }

                default:
                    break;
            }
        } catch (error) {
            console.error('Error procesando mensaje:', error);
        }
    });

    ws.on('close', () => {
        const meta = clients.get(ws);
        const username = meta ? meta.username : null;
        clients.delete(ws);
        console.log(`Cliente desconectado: ${username}. Total: ${clients.size}`);

        if (username) {
            broadcast({
                type: 'system',
                event: 'leave',
                username: username,
                timestamp: new Date().toLocaleTimeString('es-ES', { hour12: false })
            });
        }
        broadcastUserCount();
    });

    ws.on('error', (error) => {
        console.error('Error WebSocket:', error);
        clients.delete(ws);
        broadcastUserCount();
    });
});

module.exports = { app, server };
