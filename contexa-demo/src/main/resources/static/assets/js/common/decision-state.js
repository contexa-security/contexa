import { t } from './i18n.js';
import { badge } from './ui.js';

export function appendDecisionState(target, decision) {
    if (decision.technicalFallback === true) {
        target.append(badge(t('report.fallback'), 'warning'));
    } else if (decision.success === false || decision.llmDecisionPresent === false) {
        target.append(badge(t('report.modelNotAccepted'), 'warning'));
    }
    if (decision.failureType) target.append(badge(`${t('report.failure')}: ${decision.failureType}`, 'warning'));
}
