import { t } from './i18n.js';
import { ApiError } from './http.js';
import { badge, byId, notice } from './ui.js';
import { showWorkError } from './work.js';
import { isSecurityResponse } from './security-feedback.js';

export function approvalStatus(status) {
    const tone = status === 'APPROVED' ? 'good' : ['REJECTED', 'EXPIRED'].includes(status) ? 'warning' : '';
    return badge(t(`approval.status.${status}`), tone);
}

export function approvalError(error) {
    if (error instanceof ApiError && [400, 403, 404, 409].includes(error.status) && !isSecurityResponse(error.data)) {
        notice(byId('feedback'), t(`approval.error.${error.status}`), 'warning');
    } else showWorkError(error);
}
