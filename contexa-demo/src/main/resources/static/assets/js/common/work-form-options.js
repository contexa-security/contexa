import { rememberWorkPage } from './work-navigation.js';

const controls = { purpose: 'purpose', language: 'file-language', approval: 'work-approval' };

export function querySelection(key, controlId) {
    const value = new URLSearchParams(location.search).get(key);
    const control = document.getElementById(controlId);
    return value && control && [...control.options].some(option => option.value === value) ? value : null;
}

export function initialApprovalId(command) {
    const query = new URLSearchParams(location.search);
    return query.has('approval') ? query.get('approval') || null : command?.approvalId || null;
}

export function bindWorkFormOptions(username) {
    for (const [key, id] of Object.entries(controls)) {
        if (key === 'approval') continue;
        const value = querySelection(key, id);
        if (value) document.getElementById(id).value = value;
    }
    const remember = () => {
        const values = {};
        for (const [key, id] of Object.entries(controls)) {
            const control = document.getElementById(id);
            if (control) values[key] = control.value;
        }
        rememberWorkPage(username, values);
    };
    for (const id of Object.values(controls)) document.getElementById(id)?.addEventListener('change', remember);
    document.addEventListener('lab:approval', remember);
    document.addEventListener('submit', remember, true);
}
