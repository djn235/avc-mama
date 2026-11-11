/**
 * Security Engine: Client-Side Web Crypto API Architecture (AES-256-GCM + PBKDF2)
 */
class CryptoEngine {
    static async deriveKey(pin, salt) {
        const enc = new TextEncoder();
        const pinBuffer = enc.encode(pin);
        const baseKey = await window.crypto.subtle.importKey(
            'raw', pinBuffer, { name: 'PBKDF2' }, false, ['deriveKey']
        );
        return await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 600000,
                hash: 'SHA-256'
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    static async encryptData(dataObj, derivedKey) {
        const enc = new TextEncoder();
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedData = enc.encode(JSON.stringify(dataObj));

        const ciphertextBuffer = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            derivedKey,
            encodedData
        );

        return {
            iv: Array.from(iv),
            ciphertext: Array.from(new Uint8Array(ciphertextBuffer))
        };
    }

    static async decryptData(encryptedBundle, derivedKey) {
        const dec = new TextDecoder();
        const iv = new Uint8Array(encryptedBundle.iv);
        const ciphertext = new Uint8Array(encryptedBundle.ciphertext);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            derivedKey,
            ciphertext
        );

        return JSON.parse(dec.decode(decryptedBuffer));
    }
}

/**
 * Core Application State
 */
const AppState = {
    currentRole: 'patient', // 'patient' | 'helper' | 'doctor'
    activeKey: null,
    salt: null,
    isUnlocked: false,
    medications: [],
    logs: [],
    pendingTargetRole: null,
    targetEditId: null
};

// DOM Elements
const el = {
    roleBadge: document.getElementById('roleBadge'),
    netStatus: document.getElementById('netStatus'),
    cryptoStatus: document.getElementById('cryptoStatus'),
    lockedVaultBanner: document.getElementById('lockedVaultBanner'),
    btnUnlockVault: document.getElementById('btnUnlockVault'),
    btnThemeToggle: document.getElementById('btnThemeToggle'),
    btnZoomToggle: document.getElementById('btnZoomToggle'),
    btnSwitchRole: document.getElementById('btnSwitchRole'),
    viewPatient: document.getElementById('viewPatient'),
    viewHelper: document.getElementById('viewHelper'),
    viewDoctor: document.getElementById('viewDoctor'),
    patientMedList: document.getElementById('patientMedList'),
    doctorMedList: document.getElementById('doctorMedList'),
    helperLogList: document.getElementById('helperLogList'),
    dailyProgress: document.getElementById('dailyProgress'),
    statAdherence: document.getElementById('statAdherence'),
    statTaken: document.getElementById('statTaken'),
    statSnoozed: document.getElementById('statSnoozed'),
    statMissed: document.getElementById('statMissed'),
    modalPin: document.getElementById('modalPin'),
    formPin: document.getElementById('formPin'),
    inputPin: document.getElementById('inputPin'),
    pinError: document.getElementById('pinError'),
    btnCancelPin: document.getElementById('btnCancelPin'),
    modalMedForm: document.getElementById('modalMedForm'),
    formMed: document.getElementById('formMed'),
    medFormTitle: document.getElementById('medFormTitle'),
    medId: document.getElementById('medId'),
    medName: document.getElementById('medName'),
    medDosage: document.getElementById('medDosage'),
    medTime: document.getElementById('medTime'),
    medInstructions: document.getElementById('medInstructions'),
    btnOpenAddMed: document.getElementById('btnOpenAddMed'),
    btnCancelMedForm: document.getElementById('btnCancelMedForm')
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    initCryptoSalt();
    setupThemeAndZoom();
    setupNetworkListeners();
    setupEventListeners();
    registerServiceWorker();
});

function initCryptoSalt() {
    let storedSalt = localStorage.getItem('vault_salt');
    if (!storedSalt) {
        const saltArray = window.crypto.getRandomValues(new Uint8Array(16));
        storedSalt = JSON.stringify(Array.from(saltArray));
        localStorage.setItem('vault_salt', storedSalt);
    }
    AppState.salt = new Uint8Array(JSON.parse(storedSalt));
}

// Network Status Management
function setupNetworkListeners() {
    const updateNet = () => {
        if (navigator.onLine) {
            el.netStatus.textContent = "En ligne";
            el.netStatus.className = "px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300";
            syncOfflineQueue();
        } else {
            el.netStatus.textContent = "Hors ligne";
            el.netStatus.className = "px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-900 text-amber-800 dark:text-amber-200";
        }
    };
    window.addEventListener('online', updateNet);
    window.addEventListener('offline', updateNet);
    updateNet();
}

function syncOfflineQueue() {
    const queue = localStorage.getItem('offline_queue');
    if (queue) {
        localStorage.removeItem('offline_queue');
    }
}

// Event Listeners Setup
function setupEventListeners() {
    el.btnUnlockVault.addEventListener('click', () => {
        AppState.pendingTargetRole = AppState.currentRole;
        el.modalPin.classList.remove('hidden');
    });

    el.btnSwitchRole.addEventListener('click', () => {
        const roles = ['patient', 'helper', 'doctor'];
        const nextRole = roles[(roles.indexOf(AppState.currentRole) + 1) % roles.length];
        
        if (nextRole !== 'patient' && !AppState.isUnlocked) {
            AppState.pendingTargetRole = nextRole;
            el.modalPin.classList.remove('hidden');
        } else {
            switchRole(nextRole);
        }
    });

    el.btnCancelPin.addEventListener('click', () => {
        el.modalPin.classList.add('hidden');
        el.inputPin.value = '';
        el.pinError.classList.add('hidden');
    });

    el.formPin.addEventListener('submit', async (e) => {
        e.preventDefault();
        const pin = el.inputPin.value.trim();
        if (!pin) return;

        try {
            const key = await CryptoEngine.deriveKey(pin, AppState.salt);
            const encryptedVault = localStorage.getItem('encrypted_vault');

            if (encryptedVault) {
                const parsedBundle = JSON.parse(encryptedVault);
                const decrypted = await CryptoEngine.decryptData(parsedBundle, key);
                AppState.medications = decrypted.medications || [];
                AppState.logs = decrypted.logs || [];
            } else {
                AppState.medications = [];
                AppState.logs = [];
                await persistVault(key);
            }

            AppState.activeKey = key;
            AppState.isUnlocked = true;
            el.cryptoStatus.textContent = "🔓 Déverrouillé";
            el.cryptoStatus.className = "px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-900 text-emerald-800 dark:text-emerald-200";
            el.lockedVaultBanner.classList.add('hidden');
            el.modalPin.classList.add('hidden');
            el.inputPin.value = '';
            el.pinError.classList.add('hidden');

            if (AppState.pendingTargetRole) {
                switchRole(AppState.pendingTargetRole);
                AppState.pendingTargetRole = null;
            }
            renderAll();
        } catch (err) {
            el.pinError.classList.remove('hidden');
        }
    });
}

async function persistVault(keyInstance = AppState.activeKey) {
    if (!keyInstance) return;
    const payload = {
        medications: AppState.medications,
        logs: AppState.logs
    };
    const encryptedBundle = await CryptoEngine.encryptData(payload, keyInstance);
    localStorage.setItem('encrypted_vault', JSON.stringify(encryptedBundle));
}

function switchRole(targetRole) {
    AppState.currentRole = targetRole;
    el.viewPatient.classList.add('hidden');
    el.viewHelper.classList.add('hidden');
    el.viewDoctor.classList.add('hidden');

    if (targetRole === 'patient') {
        el.roleBadge.textContent = "Mode Patient";
        el.viewPatient.classList.remove('hidden');
    } else if (targetRole === 'helper') {
        el.roleBadge.textContent = "Mode Aidant";
        el.viewHelper.classList.remove('hidden');
    } else if (targetRole === 'doctor') {
        el.roleBadge.textContent = "Mode Médecin";
        el.viewDoctor.classList.remove('hidden');
    }
    renderAll();
}

// Render Functions using XSS-Safe DOM Manipulation
function renderAll() {
    renderPatientView();
    renderHelperView();
    renderDoctorView();
}

function renderPatientView() {
    el.patientMedList.textContent = '';
    if (!AppState.isUnlocked) {
        const msg = document.createElement('p');
        msg.className = "text-slate-500 text-center py-6 text-sm";
        msg.textContent = "Déverrouillez l'application pour charger les médicaments.";
        el.patientMedList.appendChild(msg);
        el.dailyProgress.textContent = "0/0 pris";
        return;
    }

    if (AppState.medications.length === 0) {
        const msg = document.createElement('p');
        msg.className = "text-slate-400 text-center py-6 text-sm";
        msg.textContent = "Aucun médicament planifié.";
        el.patientMedList.appendChild(msg);
        el.dailyProgress.textContent = "0/0 pris";
        return;
    }

    let takenCount = 0;
    AppState.medications.forEach(med => {
        const card = document.createElement('div');
        card.className = "med-card p-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 flex items-center justify-between";

        const left = document.createElement('div');
        
        const title = document.createElement('h3');
        title.className = "med-title font-bold text-lg text-slate-900 dark:text-slate-100";
        title.textContent = med.name; // Safe Assignment

        const details = document.createElement('p');
        details.className = "text-xs text-slate-500 dark:text-slate-400";
        details.textContent = `${med.dosage} - Prise à ${med.time} (${med.instructions || 'Aucune instruction'})`;

        left.appendChild(title);
        left.appendChild(details);

        const btn = document.createElement('button');
        btn.className = "px-4 py-2.5 rounded-xl text-sm font-bold shadow-sm transition active:scale-95 bg-emerald-600 hover:bg-emerald-700 text-white";
        btn.textContent = "PRIS";
        btn.addEventListener('click', () => logDoseAction(med.id, 'taken'));

        card.appendChild(left);
        card.appendChild(btn);
        el.patientMedList.appendChild(card);
    });

    el.dailyProgress.textContent = `${takenCount}/${AppState.medications.length} pris`;
}

function renderHelperView() {
    el.helperLogList.textContent = '';
    if (AppState.logs.length === 0) {
        const empty = document.createElement('p');
        empty.className = "text-slate-400 text-center py-4 text-xs";
        empty.textContent = "Aucun historique de prise disponible.";
        el.helperLogList.appendChild(empty);
        return;
    }

    AppState.logs.slice().reverse().forEach(log => {
        const item = document.createElement('div');
        item.className = "p-2 rounded-lg bg-slate-100 dark:bg-slate-700/50 flex justify-between items-center text-xs";

        const label = document.createElement('span');
        label.textContent = `${log.medName} - ${log.action === 'taken' ? 'Pris' : 'Ignoré'}`;
        
        const time = document.createElement('span');
        time.className = "text-slate-400 font-mono";
        time.textContent = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        item.appendChild(label);
        item.appendChild(time);
        el.helperLogList.appendChild(item);
    });

    const total = AppState.logs.length;
    const taken = AppState.logs.filter(l => l.action === 'taken').length;
    const rate = total > 0 ? Math.round((taken / total) * 100) : 100;
    el.statAdherence.textContent = `${rate}%`;
    el.statTaken.textContent = taken;
}

function renderDoctorView() {
    el.doctorMedList.textContent = '';
    if (!AppState.isUnlocked) {
        const msg = document.createElement('p');
        msg.className = "text-slate-400 text-center py-4 text-sm";
        msg.textContent = "Coffre verrouillé. Déverrouillez pour modifier les ordonnances.";
        el.doctorMedList.appendChild(msg);
        return;
    }

    AppState.medications.forEach(med => {
        const card = document.createElement('div');
        card.className = "med-card p-3 rounded-xl border border-slate-200 dark:border-slate-700 flex justify-between items-center";

        const info = document.createElement('div');
        const title = document.createElement('h4');
        title.className = "med-title font-bold text-slate-800 dark:text-slate-200";
        title.textContent = `${med.name} (${med.dosage})`;

        const sub = document.createElement('p');
        sub.className = "text-xs text-slate-500";
        sub.textContent = `Heure: ${med.time} | ${med.instructions || 'S.O.'}`;

        info.appendChild(title);
        info.appendChild(sub);

        const actions = document.createElement('div');
        actions.className = "flex space-x-2";

        const btnEdit = document.createElement('button');
        btnEdit.className = "px-2 py-1 bg-slate-200 dark:bg-slate-600 rounded text-xs font-semibold";
        btnEdit.textContent = "Modifier";
        btnEdit.addEventListener('click', () => openEditMedModal(med));

        const btnDelete = document.createElement('button');
        btnDelete.className = "px-2 py-1 bg-rose-500 text-white rounded text-xs font-semibold hover:bg-rose-600";
        btnDelete.textContent = "Supprimer";
        btnDelete.addEventListener('click', () => deleteMedication(med.id));

        actions.appendChild(btnEdit);
        actions.appendChild(btnDelete);
        card.appendChild(info);
        card.appendChild(actions);
        el.doctorMedList.appendChild(card);
    });
}

async function logDoseAction(medId, action) {
    const med = AppState.medications.find(m => m.id === medId);
    if (!med) return;

    const logEntry = {
        id: crypto.randomUUID(),
        medId: med.id,
        medName: med.name,
        action: action,
        timestamp: new Date().toISOString()
    };

    AppState.logs.push(logEntry);
    if (!navigator.onLine) {
        const queue = JSON.parse(localStorage.getItem('offline_queue') || '[]');
        queue.push(logEntry);
        localStorage.setItem('offline_queue', JSON.stringify(queue));
    }

    await persistVault();
    renderAll();
}

// Doctor Medication Management
el.btnOpenAddMed.addEventListener('click', () => {
    if (!AppState.isUnlocked) return;
    AppState.targetEditId = null;
    el.medFormTitle.textContent = "Ajouter un médicament";
    el.formMed.reset();
    el.modalMedForm.classList.remove('hidden');
});

el.btnCancelMedForm.addEventListener('click', () => {
    el.modalMedForm.classList.add('hidden');
});

function openEditMedModal(med) {
    AppState.targetEditId = med.id;
    el.medFormTitle.textContent = "Modifier le médicament";
    el.medName.value = med.name;
    el.medDosage.value = med.dosage;
    el.medTime.value = med.time;
    el.medInstructions.value = med.instructions || '';
    el.modalMedForm.classList.remove('hidden');
}

el.formMed.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!AppState.isUnlocked) return;

    const newMed = {
        id: AppState.targetEditId || crypto.randomUUID(),
        name: el.medName.value.trim(),
        dosage: el.medDosage.value.trim(),
        time: el.medTime.value,
        instructions: el.medInstructions.value.trim()
    };

    if (AppState.targetEditId) {
        const idx = AppState.medications.findIndex(m => m.id === AppState.targetEditId);
        if (idx !== -1) AppState.medications[idx] = newMed;
    } else {
        AppState.medications.push(newMed);
    }

    await persistVault();
    el.modalMedForm.classList.add('hidden');
    renderAll();
});

async function deleteMedication(id) {
    if (!AppState.isUnlocked) return;
    AppState.medications = AppState.medications.filter(m => m.id !== id);
    await persistVault();
    renderAll();
}

// Accessibility & Themes
function setupThemeAndZoom() {
    el.btnThemeToggle.addEventListener('click', () => {
        document.documentElement.classList.toggle('dark');
    });

    el.btnZoomToggle.addEventListener('click', () => {
        document.documentElement.classList.toggle('font-zoom-active');
    });
}

// Service Worker Isolation
function registerServiceWorker() {
    if ('serviceWorker' in navigator) {
        const swCode = `
            self.addEventListener('install', e => self.skipWaiting());
            self.addEventListener('activate', e => e.waitUntil(clients.claim()));
            self.addEventListener('fetch', e => {
                e.respondWith(fetch(e.request).catch(() => new Response('Offline')));
            });
        `;
        const blob = new Blob([swCode], { type: 'application/javascript' });
        const blobUrl = URL.createObjectURL(blob);
        navigator.serviceWorker.register(blobUrl).catch(() => {});
    }
}