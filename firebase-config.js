require('dotenv').config();

const admin = require('firebase-admin');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const fs = require('fs');
const path = require('path');

// ============================================
// INICIALIZACIÓN DE FIREBASE ADMIN SDK v14+
// ============================================

let firebaseApp = null;
let auth = null;
let firestore = null;

/**
 * Inicializa Firebase Admin SDK.
 * Usa el archivo de clave privada (Service Account) descargado de Firebase Console.
 */
function initializeFirebase() {
    if (firebaseApp) return { auth, firestore, FieldValue };

    const serviceAccountPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || './firebase-service-account.json';

    try {
        if (!fs.existsSync(serviceAccountPath)) {
            throw new Error(
                'No se encontró el archivo de Service Account en: ' + path.resolve(serviceAccountPath)
            );
        }

        const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, 'utf8'));

        // firebase-admin v14+: admin.cert() directamente (no admin.credential.cert())
        firebaseApp = admin.initializeApp({
            credential: admin.cert(serviceAccount),
            databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
        });

        // Obtener instancias de Auth y Firestore
        auth = getAuth(firebaseApp);
        firestore = getFirestore(firebaseApp);

        console.log('Firebase Admin SDK inicializado correctamente');
        console.log('  Proyecto:', serviceAccount.project_id);
        console.log('  Auth:     ACTIVO');
        console.log('  Firestore: ACTIVO');

        return { auth, firestore, FieldValue };

    } catch (error) {
        console.error('ERROR al inicializar Firebase:', error.message);
        console.error('');
        console.error('Para usar Firebase real necesitas:');
        console.error('  1. Firebase Console -> Project Settings -> Service Accounts');
        console.error('  2. Generar nueva clave privada (descarga un archivo .json)');
        console.error('  3. Colocarlo en: ' + path.resolve(serviceAccountPath));
        console.error('');
        return { auth: null, firestore: null, FieldValue: null };
    }
}

/**
 * Crea un usuario en Firebase Authentication.
 * @returns {Promise<{success: boolean, uid?: string, error?: string}>}
 */
async function createFirebaseUser(username, password) {
    const { auth: firebaseAuth } = initializeFirebase();

    if (!firebaseAuth) {
        return { success: false, error: 'Firebase no está inicializado' };
    }

    try {
        // Firebase requiere email, usamos un email sintético
        const email = `${username.toLowerCase()}@epn-chat.local`;

        const userRecord = await firebaseAuth.createUser({
            email: email,
            password: password,
            displayName: username
        });

        return { success: true, uid: userRecord.uid };
    } catch (error) {
        if (error.code === 'auth/email-already-exists') {
            return { success: false, error: 'El usuario ya existe' };
        }
        if (error.code === 'auth/invalid-password') {
            return { success: false, error: 'La contraseña debe tener al menos 6 caracteres' };
        }
        console.error('Error creando usuario en Firebase:', error.message);
        return { success: false, error: 'Error al registrar usuario: ' + error.message };
    }
}

/**
 * Verifica las credenciales del usuario.
 * Firebase Admin SDK no tiene un método directo para verificar password,
 * así que verificamos el usuario existe en Auth y comparamos el hash bcrypt
 * almacenado en Firestore.
 *
 * @returns {Promise<{success: boolean, uid?: string, error?: string}>}
 */
async function verifyFirebaseUser(username, password) {
    const { auth: firebaseAuth, firestore: db } = initializeFirebase();

    if (!firebaseAuth) {
        return { success: false, error: 'Firebase no está inicializado' };
    }

    try {
        const email = `${username.toLowerCase()}@epn-chat.local`;

        // Verificar que el usuario existe en Firebase Auth
        const userRecord = await firebaseAuth.getUserByEmail(email);

        // Verificar el password contra el hash almacenado en Firestore
        const bcrypt = require('bcryptjs');
        const userDoc = await db.collection('users').doc(userRecord.uid).get();

        if (!userDoc.exists) {
            return { success: false, error: 'Usuario o password incorrectos' };
        }

        const data = userDoc.data();
        const passwordValid = await bcrypt.compare(password, data.passwordHash);

        if (!passwordValid) {
            return { success: false, error: 'Usuario o password incorrectos' };
        }

        return { success: true, uid: userRecord.uid };
    } catch (error) {
        if (error.code === 'auth/user-not-found') {
            return { success: false, error: 'Usuario o password incorrectos' };
        }
        console.error('Error verificando usuario:', error.message);
        return { success: false, error: 'Error al verificar usuario' };
    }
}

/**
 * Guarda un mensaje en Firestore (base de datos real).
 */
async function saveMessageToFirestore(username, text, timestamp) {
    const { firestore: db, FieldValue: fv } = initializeFirebase();

    if (!db) {
        console.error('Firestore no disponible, mensaje no guardado');
        return null;
    }

    try {
        const docRef = await db.collection('messages').add({
            username: username,
            text: text,
            timestamp: timestamp,
            createdAt: fv.serverTimestamp()
        });
        return { id: docRef.id, username, text, timestamp };
    } catch (error) {
        console.error('Error guardando mensaje en Firestore:', error.message);
        return null;
    }
}

/**
 * Obtiene el historial de mensajes desde Firestore.
 */
async function getMessagesFromFirestore(limit = 50) {
    const { firestore: db } = initializeFirebase();

    if (!db) {
        return [];
    }

    try {
        const snapshot = await db.collection('messages')
            .orderBy('createdAt', 'asc')
            .limit(limit)
            .get();

        const messages = snapshot.docs.map(doc => {
            const data = doc.data();
            return {
                id: doc.id,
                username: data.username,
                text: data.text,
                timestamp: data.timestamp
            };
        });

        return messages;
    } catch (error) {
        console.error('Error leyendo mensajes de Firestore:', error.message);
        return [];
    }
}

/**
 * Guarda el hash del password en Firestore (para verificación posterior).
 */
async function saveUserPasswordHash(uid, password) {
    const { firestore: db, FieldValue: fv } = initializeFirebase();
    const bcrypt = require('bcryptjs');

    if (!db) return;

    try {
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        await db.collection('users').doc(uid).set({
            passwordHash: passwordHash,
            updatedAt: fv.serverTimestamp()
        }, { merge: true });
    } catch (error) {
        console.error('Error guardando hash en Firestore:', error.message);
    }
}

module.exports = {
    initializeFirebase,
    createFirebaseUser,
    verifyFirebaseUser,
    saveMessageToFirestore,
    getMessagesFromFirestore,
    saveUserPasswordHash
};
