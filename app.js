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
    initMedicationTimer(); // Surveillance des retards
});

// Theme & Accessibility Zoom Management
function setupThemeAndZoom() {
    if (localStorage.getItem('theme') === 'dark') {
        document.documentElement.classList.add('dark');
        el.btnThemeToggle.textContent = '☀️';
    }
    if (localStorage.getItem('font_zoom') === 'true') {
        document.documentElement.classList.add('font-zoom-active');
    }

    el.btnThemeToggle.onclick = () => {
        const isDark = document.documentElement.classList.toggle('dark');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        el.btnThemeToggle.textContent = isDark ? '☀️' : '🌙';
    };

    el.btnZoomToggle.onclick = () => {
        const isZoomed = document.documentElement.classList.toggle('font-zoom-active');
        localStorage.setItem('font_zoom', isZoomed ? 'true' : 'false');
    };
}

// Refresh Patient View every minute to flag overdue doses (> 30 min)
function initMedicationTimer() {
    setInterval(() => {
        if (AppState.isUnlocked && AppState.currentRole === 'patient') {
            renderPatientView();
        }
    }, 60000);
}

// Modal Helpers (Toggle hidden <-> flex cleanly)
function openModal(modalEl) {
    modalEl.classList.remove('hidden');
    modalEl.classList.add('flex');
}

function closeModal(modalEl) {
    modalEl.classList.add('hidden');
    modalEl.classList.remove('flex');
}

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
    el.btnUnlockVault.onclick = () => {
        AppState.pendingTargetRole = AppState.currentRole;
        openModal(el.modalPin);
        el.inputPin.focus();
    };

    el.btnSwitchRole.onclick = () => {
        const roles = ['patient', 'helper', 'doctor'];
        const nextRole = roles[(roles.indexOf(AppState.currentRole) + 1) % roles.length];
        
        if (nextRole !== 'patient' && !AppState.isUnlocked) {
            AppState.pendingTargetRole = nextRole;
            openModal(el.modalPin);
            el.inputPin.focus();
        } else {
            switchRole(nextRole);
        }
    };

    el.btnCancelPin.onclick = () => {
        closeModal(el.modalPin);
        el.inputPin.value = '';
        el.pinError.classList.add('hidden');
    };

    el.formPin.onsubmit = async (e) => {
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
            closeModal(el.modalPin);
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
    };

    const filterSpecialtyEl = document.getElementById('filterSpecialty');
    if (filterSpecialtyEl) {
        filterSpecialtyEl.onchange = () => {
            renderDoctorView();
        };
    }
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

    const now = new Date();
    const todayStr = now.toISOString().split('T')[0];
    const currentMinutes = now.getHours() * 60 + now.getMinutes();

    let takenCount = 0;

    AppState.medications.forEach(med => {
        const todayLog = AppState.logs.find(log => 
            log.medId === med.id && 
            log.timestamp.startsWith(todayStr)
        );

        const isTaken = todayLog && todayLog.action === 'taken';
        const isMissed = todayLog && todayLog.action === 'missed';

        if (isTaken) takenCount++;

        // Calcul du retard (> 30 minutes après l'heure prévue et non pris)
        const [medH, medM] = med.time.split(':').map(Number);
        const medMinutes = medH * 60 + medM;
        const isOverdue = !isTaken && !isMissed && (currentMinutes - medMinutes >= 30);

        // Style dynamique de toute la ligne (carte) avec surbrillance verte ou orange/jaune
        const card = document.createElement('div');
        card.className = `med-card p-4 rounded-xl border transition-all duration-300 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 ${
            isTaken 
                ? 'border-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 dark:border-emerald-600 shadow-md' 
                : isMissed
                ? 'border-rose-300 bg-rose-50/50 dark:bg-rose-950/20 dark:border-rose-800'
                : isOverdue
                ? 'border-amber-400 bg-amber-50 dark:bg-amber-950/40 dark:border-amber-600 animate-pulse'
                : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900'
        }`;

        const left = document.createElement('div');
        
        const titleContainer = document.createElement('div');
        titleContainer.className = "flex items-center space-x-2 flex-wrap";

        const title = document.createElement('h3');
        title.className = "med-title font-bold text-lg text-slate-900 dark:text-slate-100";
        title.textContent = med.name;

        const specialtyBadge = document.createElement('span');
        specialtyBadge.className = "px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200";
        specialtyBadge.textContent = med.specialty || 'Autres-Généraliste';

        titleContainer.appendChild(title);
        titleContainer.appendChild(specialtyBadge);

        if (isTaken) {
            const checkBadge = document.createElement('span');
            checkBadge.className = "text-emerald-600 dark:text-emerald-400 font-extrabold text-lg";
            checkBadge.textContent = "✓";
            titleContainer.appendChild(checkBadge);
        } else if (isOverdue) {
            const warningBadge = document.createElement('span');
            warningBadge.className = "px-2 py-0.5 rounded text-[10px] bg-amber-200 dark:bg-amber-900 text-amber-800 dark:text-amber-200 font-bold uppercase";
            warningBadge.textContent = "⚠️ En retard";
            titleContainer.appendChild(warningBadge);
        }

        const details = document.createElement('p');
        details.className = "text-xs text-slate-500 dark:text-slate-400 mt-1";
        details.textContent = `${med.dosage} - Prise prévue à ${med.time} (${med.instructions || 'Aucune instruction'})`;

        left.appendChild(titleContainer);
        left.appendChild(details);

        const actionsDiv = document.createElement('div');
        actionsDiv.className = "flex items-center space-x-2 w-full md:w-auto justify-end";

        // Bouton Toggle : Clic 1 = Valider Pris, Clic 2 = Annuler (état initial)
        const btnTake = document.createElement('button');
        
        if (isTaken) {
            btnTake.className = "px-6 py-3 rounded-2xl text-sm font-extrabold bg-emerald-600 hover:bg-emerald-700 text-white shadow-md flex items-center space-x-2 transition cursor-pointer";
            btnTake.innerHTML = "<span>✓</span><span>DÉJÀ PRIS (ANNULER)</span>";
        } else {
            btnTake.className = "px-6 py-3 rounded-2xl text-base font-extrabold shadow-md transition transform active:scale-95 bg-emerald-600 hover:bg-emerald-700 text-white cursor-pointer flex items-center space-x-2";
            btnTake.innerHTML = "<span>💊</span><span>PRENDRE</span>";
        }

        btnTake.onclick = async () => {
            if ('vibrate' in navigator) navigator.vibrate(80);

            if (isTaken) {
                // CLIC 2 : Annulation (Retour à l'état initial)
                await removeTodayLog(med.id);
            } else {
                // CLIC 1 : Validation de la prise
                await handlePatientToggleDose(med.id, 'taken');
            }
        };

        // Bouton Ignorer
        if (!isTaken) {
            const btnIgn = document.createElement('button');
            btnIgn.className = `px-3 py-3 rounded-xl text-xs font-semibold transition ${
                isMissed 
                    ? 'bg-rose-600 text-white' 
                    : 'bg-slate-200 dark:bg-slate-700 hover:bg-rose-100 text-slate-700 dark:text-slate-300'
            }`;
            btnIgn.textContent = isMissed ? "Ignoré" : "Ignorer";
            btnIgn.onclick = async () => {
                if ('vibrate' in navigator) navigator.vibrate(50);
                await handlePatientToggleDose(med.id, isMissed ? 'cancel' : 'missed');
            };
            actionsDiv.appendChild(btnIgn);
        }

        actionsDiv.appendChild(btnTake);
        card.appendChild(left);
        card.appendChild(actionsDiv);
        el.patientMedList.appendChild(card);
    });

    el.dailyProgress.textContent = `${takenCount}/${AppState.medications.length} pris`;
}

async function handlePatientToggleDose(medId, actionType) {
    const todayStr = new Date().toISOString().split('T')[0];

    // Nettoyer tout ancien log du jour pour ce médicament pour repartir sur une base propre
    AppState.logs = AppState.logs.filter(log => !(log.medId === medId && log.timestamp.startsWith(todayStr)));

    if (actionType !== 'cancel') {
        const med = AppState.medications.find(m => m.id === medId);
        const logEntry = {
            id: crypto.randomUUID(),
            medId: med.id,
            medName: med.name,
            action: actionType,
            timestamp: new Date().toISOString()
        };
        AppState.logs.push(logEntry);

        if (!navigator.onLine) {
            const queue = JSON.parse(localStorage.getItem('offline_queue') || '[]');
            queue.push(logEntry);
            localStorage.setItem('offline_queue', JSON.stringify(queue));
        }
    }

    await persistVault();
    renderAll();
}

async function removeTodayLog(medId) {
    const todayStr = new Date().toISOString().split('T')[0];
    AppState.logs = AppState.logs.filter(log => !(log.medId === medId && log.timestamp.startsWith(todayStr)));
    await persistVault();
    renderAll();
}

function renderHelperView() {
    el.helperLogList.textContent = '';
    const helperMissedList = document.getElementById('helperMissedList');
    if (helperMissedList) helperMissedList.textContent = '';

    const todayStr = new Date().toISOString().split('T')[0];

    const totalLogs = AppState.logs.length;
    const takenLogs = AppState.logs.filter(l => l.action === 'taken');
    const snoozedLogs = AppState.logs.filter(l => l.action === 'snoozed');
    const missedLogs = AppState.logs.filter(l => l.action === 'missed');

    const rate = totalLogs > 0 ? Math.round((takenLogs.length / totalLogs) * 100) : 100;
    
    if (el.statAdherence) el.statAdherence.textContent = `${rate}%`;
    if (el.statTaken) el.statTaken.textContent = takenLogs.length;
    if (el.statSnoozed) el.statSnoozed.textContent = snoozedLogs.length;
    if (el.statMissed) el.statMissed.textContent = missedLogs.length;

    const todayIssues = AppState.logs.filter(l => 
        (l.action === 'missed' || l.action === 'snoozed') && 
        l.timestamp.startsWith(todayStr)
    );

    if (helperMissedList) {
        if (todayIssues.length === 0) {
            const okMsg = document.createElement('p');
            okMsg.className = "text-slate-500 dark:text-slate-400 text-xs";
            okMsg.textContent = "Aucune anomalie signalée aujourd'hui.";
            helperMissedList.appendChild(okMsg);
        } else {
            todayIssues.forEach(issue => {
                const badge = document.createElement('div');
                badge.className = "p-2 rounded bg-white dark:bg-slate-900 border border-rose-200 dark:border-rose-900 flex justify-between items-center";
                
                const text = document.createElement('span');
                text.className = "font-medium text-rose-700 dark:text-rose-300";
                text.textContent = `• ${issue.medName} (${issue.action === 'snoozed' ? 'Repoussé' : 'Manqué'})`;

                const time = document.createElement('span');
                time.className = "text-slate-400 font-mono text-[10px]";
                time.textContent = new Date(issue.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

                badge.appendChild(text);
                badge.appendChild(time);
                helperMissedList.appendChild(badge);
            });
        }
    }

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
        let actionText = 'Pris';
        if (log.action === 'snoozed') actionText = 'Repoussé';
        if (log.action === 'missed') actionText = 'Ignoré/Manqué';
        
        label.textContent = `${log.medName} - ${actionText}`;
        
        const time = document.createElement('span');
        time.className = "text-slate-400 font-mono";
        time.textContent = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        item.appendChild(label);
        item.appendChild(time);
        el.helperLogList.appendChild(item);
    });
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

    const selectedFilter = document.getElementById('filterSpecialty')?.value || 'ALL';

    // Filtrer les médicaments selon la spécialité sélectionnée
    const filteredMeds = AppState.medications.filter(med => {
        if (selectedFilter === 'ALL') return true;
        return (med.specialty || 'Autres-Généraliste') === selectedFilter;
    });

    if (filteredMeds.length === 0) {
        const msg = document.createElement('p');
        msg.className = "text-slate-400 text-center py-4 text-sm";
        msg.textContent = "Aucun médicament trouvé pour cette spécialité.";
        el.doctorMedList.appendChild(msg);
        return;
    }

    filteredMeds.forEach(med => {
        const card = document.createElement('div');
        card.className = "med-card p-3 rounded-xl border border-slate-200 dark:border-slate-700 flex flex-col md:flex-row justify-between items-start md:items-center gap-2";

        const info = document.createElement('div');
        
        const titleRow = document.createElement('div');
        titleRow.className = "flex items-center space-x-2 flex-wrap";

        const title = document.createElement('h4');
        title.className = "med-title font-bold text-slate-800 dark:text-slate-200";
        title.textContent = `${med.name} (${med.dosage})`;

        const specialtyBadge = document.createElement('span');
        specialtyBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200";
        specialtyBadge.textContent = med.specialty || 'Autres-Généraliste';

        titleRow.appendChild(title);
        titleRow.appendChild(specialtyBadge);

        const sub = document.createElement('p');
        sub.className = "text-xs text-slate-500 mt-1";
        sub.textContent = `Heure: ${med.time} | ${med.instructions || 'Aucune instruction'}`;

        info.appendChild(titleRow);
        info.appendChild(sub);

        const actions = document.createElement('div');
        actions.className = "flex space-x-2 self-end md:self-center";

        const btnEdit = document.createElement('button');
        btnEdit.className = "px-2.5 py-1 bg-slate-200 dark:bg-slate-600 rounded text-xs font-semibold hover:bg-slate-300";
        btnEdit.textContent = "Modifier";
        btnEdit.onclick = () => openEditMedModal(med);

        const btnDelete = document.createElement('button');
        btnDelete.className = "px-2.5 py-1 bg-rose-500 text-white rounded text-xs font-semibold hover:bg-rose-600";
        btnDelete.textContent = "Supprimer";
        btnDelete.onclick = () => deleteMedication(med.id);

        actions.appendChild(btnEdit);
        actions.appendChild(btnDelete);
        card.appendChild(info);
        card.appendChild(actions);
        el.doctorMedList.appendChild(card);
    });
}

// Doctor Medication Management
el.btnOpenAddMed.onclick = () => {
    if (!AppState.isUnlocked) return;
    AppState.targetEditId = null;
    el.medFormTitle.textContent = "Ajouter un médicament";
    el.formMed.reset();
    openModal(el.modalMedForm);
};

el.btnCancelMedForm.onclick = () => {
    closeModal(el.modalMedForm);
};

function openEditMedModal(med) {
    AppState.targetEditId = med.id;
    el.medFormTitle.textContent = "Modifier le médicament";
    el.medName.value = med.name;
    el.medDosage.value = med.dosage;
    el.medTime.value = med.time;
    document.getElementById('medSpecialty').value = med.specialty || 'Autres-Généraliste';
    el.medInstructions.value = med.instructions || '';
    openModal(el.modalMedForm);
}

async function deleteMedication(medId) {
    if (!AppState.isUnlocked) return;
    AppState.medications = AppState.medications.filter(m => m.id !== medId);
    await persistVault();
    renderAll();
}

el.formMed.onsubmit = async (e) => {
    e.preventDefault();
    if (!AppState.isUnlocked) return;

    const newMed = {
        id: AppState.targetEditId || crypto.randomUUID(),
        name: el.medName.value.trim(),
        dosage: el.medDosage.value.trim(),
        time: el.medTime.value,
        specialty: document.getElementById('medSpecialty').value,
        instructions: el.medInstructions.value.trim()
    };

    if (AppState.targetEditId) {
        const idx = AppState.medications.findIndex(m => m.id === AppState.targetEditId);
        if (idx !== -1) AppState.medications[idx] = newMed;
    } else {
        AppState.medications.push(newMed);
    }

    await persistVault();
    closeModal(el.modalMedForm);
    renderAll();
};