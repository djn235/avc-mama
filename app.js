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

    // DOM Elements Cache
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
        helperMissedList: document.getElementById('helperMissedList'),
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
        medTimes: document.getElementById('medTimes'),
        medSpecialty: document.getElementById('medSpecialty'),
        filterSpecialty: document.getElementById('filterSpecialty'),
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
        initMedicationTimer();
    });

    function setupThemeAndZoom() {
        if (localStorage.getItem('theme') === 'dark') {
            document.documentElement.classList.add('dark');
            if (el.btnThemeToggle) el.btnThemeToggle.textContent = '☀️';
        }
        if (localStorage.getItem('font_zoom') === 'true') {
            document.documentElement.classList.add('font-zoom-active');
        }

        if (el.btnThemeToggle) {
            el.btnThemeToggle.onclick = () => {
                const isDark = document.documentElement.classList.toggle('dark');
                localStorage.setItem('theme', isDark ? 'dark' : 'light');
                el.btnThemeToggle.textContent = isDark ? '☀️' : '🌙';
            };
        }

        if (el.btnZoomToggle) {
            el.btnZoomToggle.onclick = () => {
                const isZoomed = document.documentElement.classList.toggle('font-zoom-active');
                localStorage.setItem('font_zoom', isZoomed ? 'true' : 'false');
            };
        }
    }

    function initMedicationTimer() {
        setInterval(() => {
            if (AppState.isUnlocked && AppState.currentRole === 'patient') {
                renderPatientView();
            }
        }, 60000);
    }

    function openModal(modalEl) {
        if (!modalEl) return;
        modalEl.classList.remove('hidden');
        modalEl.classList.add('flex');
    }

    function closeModal(modalEl) {
        if (!modalEl) return;
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
    async function syncOfflineQueue() {
        const queueStr = localStorage.getItem('offline_queue');
        if (!queueStr) return;
        try {
            const queue = JSON.parse(queueStr);
            if (Array.isArray(queue) && queue.length > 0) {
                // Merge unique queued items into AppState.logs if missing
                queue.forEach(item => {
                    if (!AppState.logs.some(l => l.id === item.id)) {
                        AppState.logs.push(item);
                    }
                });
                if (AppState.activeKey) {
                    await persistVault();
                }
            }
            localStorage.removeItem('offline_queue');
        } catch (e) {
            console.error("Erreur de synchronisation hors-ligne:", e);
        }
    }

    function setupEventListeners() {
        if (el.btnUnlockVault) {
            el.btnUnlockVault.onclick = () => {
                AppState.pendingTargetRole = AppState.currentRole;
                openModal(el.modalPin);
                if (el.inputPin) el.inputPin.focus();
            };
        }

        if (el.btnSwitchRole) {
            el.btnSwitchRole.onclick = () => {
                const roles = ['patient', 'helper', 'doctor'];
                const nextRole = roles[(roles.indexOf(AppState.currentRole) + 1) % roles.length];

                if (!AppState.isUnlocked) {
                    AppState.pendingTargetRole = nextRole;
                    openModal(el.modalPin);
                    if (el.inputPin) el.inputPin.focus();
                } else {
                    switchRole(nextRole);
                }
            };
        }

        if (el.btnCancelPin) {
            el.btnCancelPin.onclick = () => {
                closeModal(el.modalPin);
                if (el.inputPin) el.inputPin.value = '';
                if (el.pinError) el.pinError.classList.add('hidden');
            };
        }

        if (el.formPin) {
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
                    if (el.cryptoStatus) {
                        el.cryptoStatus.textContent = "🔓 Déverrouillé";
                        el.cryptoStatus.className = "px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-900 text-emerald-800 dark:text-emerald-200";
                    }
                    if (el.lockedVaultBanner) el.lockedVaultBanner.classList.add('hidden');
                    closeModal(el.modalPin);
                    el.inputPin.value = '';
                    if (el.pinError) el.pinError.classList.add('hidden');

                    if (AppState.pendingTargetRole) {
                        switchRole(AppState.pendingTargetRole);
                        AppState.pendingTargetRole = null;
                    }
                    renderAll();
                } catch (err) {
                    if (el.pinError) el.pinError.classList.remove('hidden');
                }
            };
        }

        if (el.filterSpecialty) {
            el.filterSpecialty.onchange = () => renderDoctorView();
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
        if (el.viewPatient) el.viewPatient.classList.add('hidden');
        if (el.viewHelper) el.viewHelper.classList.add('hidden');
        if (el.viewDoctor) el.viewDoctor.classList.add('hidden');

        if (targetRole === 'patient') {
            if (el.roleBadge) el.roleBadge.textContent = "Mode Patient";
            if (el.viewPatient) el.viewPatient.classList.remove('hidden');
        } else if (targetRole === 'helper') {
            if (el.roleBadge) el.roleBadge.textContent = "Mode Aidant";
            if (el.viewHelper) el.viewHelper.classList.remove('hidden');
        } else if (targetRole === 'doctor') {
            if (el.roleBadge) el.roleBadge.textContent = "Mode Médecin";
            if (el.viewDoctor) el.viewDoctor.classList.remove('hidden');
        }
        renderAll();
    }

    function renderAll() {
        renderPatientView();
        renderHelperView();
        renderDoctorView();
    }

    function renderPatientView() {
        if (!el.patientMedList) return;
        el.patientMedList.textContent = '';

        if (!AppState.isUnlocked) {
            const msg = document.createElement('p');
            msg.className = "text-slate-500 text-center py-6 text-sm";
            msg.textContent = "Déverrouillez l'application pour charger les médicaments.";
            el.patientMedList.appendChild(msg);
            if (el.dailyProgress) el.dailyProgress.textContent = "0/0 pris";
            return;
        }

        if (AppState.medications.length === 0) {
            const msg = document.createElement('p');
            msg.className = "text-slate-400 text-center py-6 text-sm";
            msg.textContent = "Aucun médicament planifié.";
            el.patientMedList.appendChild(msg);
            if (el.dailyProgress) el.dailyProgress.textContent = "0/0 pris";
            return;
        }

        const now = new Date();
        const todayStr = now.toISOString().split('T')[0];
        const currentMinutes = now.getHours() * 60 + now.getMinutes();

        let totalDosesToday = 0;
        let takenCount = 0;

        AppState.medications.forEach(med => {
            const medTimes = Array.isArray(med.times) && med.times.length > 0
                ? med.times
                : [med.time || "08:00"];

            medTimes.forEach((timeSlot, index) => {
                totalDosesToday++;
                const doseKey = `${med.id}_${index}`;

                // Check specifically by doseKey for accurate multi-dose tracking
                const todayLog = AppState.logs.find(log =>
                    (log.doseKey === doseKey || (!log.doseKey && log.medId === med.id && index === 0)) &&
                    log.timestamp.startsWith(todayStr)
                );

                const isTaken = todayLog && todayLog.action === 'taken';
                const isMissed = todayLog && todayLog.action === 'missed';

                if (isTaken) takenCount++;

                // Calculate overdue (> 30 min after scheduled slot)
                let isOverdue = false;
                if (!isTaken && !isMissed && timeSlot) {
                    const [h, m] = timeSlot.split(':').map(Number);
                    if (!isNaN(h) && !isNaN(m)) {
                        isOverdue = (currentMinutes - (h * 60 + m)) >= 30;
                    }
                }

                const card = document.createElement('div');
                card.className = `med-card p-4 rounded-xl border transition-all duration-300 flex flex-col md:flex-row items-start
                md:items-center justify-between gap-3 ${
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
                specialtyBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200";
                specialtyBadge.textContent = med.specialty || 'Autres-Généraliste';

                titleContainer.appendChild(title);
                titleContainer.appendChild(specialtyBadge);

                if (isTaken) {
                    const checkBadge = document.createElement('span');
                    checkBadge.className = "text-emerald-600 dark:text-emerald-400 font-extrabold text-sm";
                    checkBadge.textContent = "✓ Validé";
                    titleContainer.appendChild(checkBadge);
                } else if (isOverdue) {
                    const warningBadge = document.createElement('span');
                    warningBadge.className = "px-2 py-0.5 rounded text-[10px] bg-amber-200 dark:bg-amber-900 text-amber-800 dark:text-amber-200 font-bold uppercase";
                    warningBadge.textContent = "⚠️ En retard";
                    titleContainer.appendChild(warningBadge);
                }

                const details = document.createElement('p');
                details.className = "text-xs text-slate-500 dark:text-slate-400 mt-1";
                details.textContent = `${med.dosage} — 🕒 Prise prévue à ${timeSlot} (${med.instructions || 'Aucune consigne'})`;

                left.appendChild(titleContainer);
                left.appendChild(details);

                const actionsDiv = document.createElement('div');
                actionsDiv.className = "flex items-center space-x-2 w-full md:w-auto justify-end";

                // Take / Cancel Toggle Button
                const btnTake = document.createElement('button');
                if (isTaken) {
                    btnTake.className = "px-5 py-2.5 rounded-2xl text-xs font-extrabold bg-emerald-600 hover:bg-emerald-700 text-white shadow-md flex items-center space-x-1 cursor-pointer";
                    btnTake.innerHTML = "<span>✓ PRIS (ANNULER)</span>";
                } else {
                    btnTake.className = "px-5 py-2.5 rounded-2xl text-sm font-extrabold shadow-md transition transform active:scale-95 bg-emerald-600 hover:bg-emerald-700 text-white cursor-pointer flex items-center space-x-1";
                    btnTake.innerHTML = "<span>💊 PRENDRE</span>";
                }

                btnTake.onclick = async () => {
                    if ('vibrate' in navigator) navigator.vibrate(80);
                    if (isTaken) {
                        await removeDoseLog(doseKey);
                    } else {
                        await logSpecificDose(med, doseKey, timeSlot, 'taken');
                    }
                };

                // Missed / Ignored Toggle Button
                if (!isTaken) {
                    const btnIgn = document.createElement('button');
                    btnIgn.className = `px-3 py-2.5 rounded-xl text-xs font-semibold transition cursor-pointer ${
                        isMissed
                            ? 'bg-rose-600 text-white'
                            : 'bg-slate-200 dark:bg-slate-700 hover:bg-rose-100 text-slate-700 dark:text-slate-300'
                    }`;
                    btnIgn.textContent = isMissed ? "Ignoré (Annuler)" : "Ignorer";
                    btnIgn.onclick = async () => {
                        if ('vibrate' in navigator) navigator.vibrate(50);
                        if (isMissed) {
                            await removeDoseLog(doseKey);
                        } else {
                            await logSpecificDose(med, doseKey, timeSlot, 'missed');
                        }
                    };
                    actionsDiv.appendChild(btnIgn);
                }

                actionsDiv.appendChild(btnTake);
                card.appendChild(left);
                card.appendChild(actionsDiv);
                el.patientMedList.appendChild(card);
            });
        });

        if (el.dailyProgress) {
            el.dailyProgress.textContent = `${takenCount}/${totalDosesToday} pris`;
        }
    }

    async function logSpecificDose(med, doseKey, timeSlot, actionType) {
        const todayStr = new Date().toISOString().split('T')[0];

        // Remove existing log for this specific slot today
        AppState.logs = AppState.logs.filter(log =>
            !(log.doseKey === doseKey && log.timestamp.startsWith(todayStr))
        );

        const logEntry = {
            id: crypto.randomUUID(),
            medId: med.id,
            doseKey: doseKey,
            timeSlot: timeSlot,
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

        await persistVault();
        renderAll();
    }

    async function removeDoseLog(doseKey) {
        const todayStr = new Date().toISOString().split('T')[0];
        AppState.logs = AppState.logs.filter(log =>
            !(log.doseKey === doseKey && log.timestamp.startsWith(todayStr))
        );
        await persistVault();
        renderAll();
    }

    function renderHelperView() {
        if (el.helperLogList) el.helperLogList.textContent = '';
        if (el.helperMissedList) el.helperMissedList.textContent = '';

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

        if (el.helperMissedList) {
            if (todayIssues.length === 0) {
                const okMsg = document.createElement('p');
                okMsg.className = "text-slate-500 dark:text-slate-400 text-xs";
                okMsg.textContent = "Aucune anomalie signalée aujourd'hui.";
                el.helperMissedList.appendChild(okMsg);
            } else {
                todayIssues.forEach(issue => {
                    const badge = document.createElement('div');
                    badge.className = "p-2 rounded bg-white dark:bg-slate-900 border border-rose-200 dark:border-rose-900 flex justify-between items-center";

                    const text = document.createElement('span');
                    text.className = "font-medium text-rose-700 dark:text-rose-300";
                    const slotInfo = issue.timeSlot ? ` (${issue.timeSlot})` : '';
                    text.textContent = `• ${issue.medName}${slotInfo} — ${issue.action === 'snoozed' ? 'Repoussé' : 'Manqué'}`;

                    const time = document.createElement('span');
                    time.className = "text-slate-400 font-mono text-[10px]";
                    time.textContent = new Date(issue.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

                    badge.appendChild(text);
                    badge.appendChild(time);
                    el.helperMissedList.appendChild(badge);
                });
            }
        }

        if (!el.helperLogList) return;

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

            const slotText = log.timeSlot ? ` [${log.timeSlot}]` : '';
            label.textContent = `${log.medName}${slotText} - ${actionText}`;

            const time = document.createElement('span');
            time.className = "text-slate-400 font-mono";
            time.textContent = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

            item.appendChild(label);
            item.appendChild(time);
            el.helperLogList.appendChild(item);
        });
    }

    function renderDoctorView() {
        if (!el.doctorMedList) return;
        el.doctorMedList.textContent = '';

        if (!AppState.isUnlocked) {
            const msg = document.createElement('p');
            msg.className = "text-slate-400 text-center py-4 text-sm";
            msg.textContent = "Coffre verrouillé. Déverrouillez pour modifier les ordonnances.";
            el.doctorMedList.appendChild(msg);
            return;
        }

        const selectedFilter = el.filterSpecialty?.value || 'ALL';

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
            const displayTimes = Array.isArray(med.times) && med.times.length > 0
                ? med.times.join(', ')
                : (med.time || 'Non spécifié');
            sub.textContent = `Heures: ${displayTimes} | ${med.instructions || 'Aucune instruction'}`;

            info.appendChild(titleRow);
            info.appendChild(sub);

            const actions = document.createElement('div');
            actions.className = "flex space-x-2 self-end md:self-center";

            const btnEdit = document.createElement('button');
            btnEdit.className = "px-2.5 py-1 bg-slate-200 dark:bg-slate-600 rounded text-xs font-semibold hover:bg-slate-300 cursor-pointer";
            btnEdit.textContent = "Modifier";
            btnEdit.onclick = () => openEditMedModal(med);

            const btnDelete = document.createElement('button');
            btnDelete.className = "px-2.5 py-1 bg-rose-500 text-white rounded text-xs font-semibold hover:bg-rose-600 cursor-pointer";
            btnDelete.textContent = "Supprimer";
            btnDelete.onclick = () => deleteMedication(med.id);

            actions.appendChild(btnEdit);
            actions.appendChild(btnDelete);
            card.appendChild(info);
            card.appendChild(actions);
            el.doctorMedList.appendChild(card);
        });
    }

    if (el.btnOpenAddMed) {
        el.btnOpenAddMed.onclick = () => {
            if (!AppState.isUnlocked) return;
            AppState.targetEditId = null;
            if (el.medFormTitle) el.medFormTitle.textContent = "Ajouter un médicament";
            if (el.formMed) el.formMed.reset();
            openModal(el.modalMedForm);
        };
    }

    if (el.btnCancelMedForm) {
        el.btnCancelMedForm.onclick = () => {
            closeModal(el.modalMedForm);
        };
    }

    function openEditMedModal(med) {
        AppState.targetEditId = med.id;
        if (el.medFormTitle) el.medFormTitle.textContent = "Modifier le médicament";
        if (el.medName) el.medName.value = med.name || '';
        if (el.medDosage) el.medDosage.value = med.dosage || '';
        if (el.medTime) el.medTime.value = med.time || (med.times && med.times[0]) || '';
        if (el.medTimes) {
            el.medTimes.value = Array.isArray(med.times) ? med.times.join(', ') : (med.time || '');
        }
        if (el.medSpecialty) el.medSpecialty.value = med.specialty || 'Autres-Généraliste';
        if (el.medInstructions) el.medInstructions.value = med.instructions || '';
        openModal(el.modalMedForm);
    }

    async function deleteMedication(medId) {
        if (!AppState.isUnlocked) return;
        AppState.medications = AppState.medications.filter(m => m.id !== medId);
        await persistVault();
        renderAll();
    }

    if (el.formMed) {
        el.formMed.onsubmit = async (e) => {
            e.preventDefault();
            if (!AppState.isUnlocked) return;

            // Parse medTimes if available, or fallback to single medTime
            let timesArray = [];
            if (el.medTimes && el.medTimes.value.trim().length > 0) {
                timesArray = el.medTimes.value
                    .split(',')
                    .map(t => t.trim())
                    .filter(t => t.length > 0);
            } else if (el.medTime && el.medTime.value) {
                timesArray = [el.medTime.value.trim()];
            }

            if (timesArray.length === 0) {
                timesArray = ['08:00'];
            }

            const newMed = {
                id: AppState.targetEditId || crypto.randomUUID(),
                name: el.medName?.value.trim() || 'Médicament',
                dosage: el.medDosage?.value.trim() || '',
                time: timesArray[0],
                times: timesArray,
                specialty: el.medSpecialty?.value || 'Autres-Généraliste',
                instructions: el.medInstructions?.value.trim() || ''
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
    }