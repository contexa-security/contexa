import { t } from './i18n.js';

const labels = Object.freeze({
    PROJECT_REVIEW: 'work.purpose.PROJECT_REVIEW',
    CUSTOMER_SUPPORT: 'work.purpose.CUSTOMER_SUPPORT',
    CROSS_PROJECT_REVIEW: 'work.purpose.CROSS_PROJECT_REVIEW',
    UNDECLARED: 'work.purpose.UNDECLARED',
    APPROVED_BULK_DELIVERY: 'approval.purpose.APPROVED_BULK_DELIVERY',
    EMERGENCY_MAINTENANCE: 'approval.purpose.EMERGENCY_MAINTENANCE'
});

export function workPurposeText(purpose) {
    return t(Object.hasOwn(labels, purpose) ? labels[purpose] : 'unknown');
}
