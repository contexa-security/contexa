import { currentLanguage, t } from './i18n.js';
import { appendDefinition, byId } from './ui.js';

export function renderHistoryReference(manifest) {
    const reference = manifest.historyReference;
    byId('run-history-reference').hidden = !reference;
    if (!reference) return;
    byId('run-history-report').href = `/report.html?id=${reference.reportId}`;
    const details = byId('run-history-facts'); details.replaceChildren();
    const labels = currentLanguage() === 'en'
        ? ['Application version', 'Current activity update count', 'Verified source observations']
        : ['애플리케이션 버전', '현재 활동 이력 갱신 수', '원본의 저장 일치 관측'];
    appendDefinition(details, labels[0], reference.applicationCompatibility === 'SAME_APPLICATION'
        ? t('variation.FIXED') : reference.applicationCompatibility === 'DIFFERENT_APPLICATION' ? t('variation.CHANGED') : t('unknown'));
    const history = manifest.initialConditions.find(value => value.arm === 'contexa')?.snapshot.history;
    appendDefinition(details, labels[1], history?.updates == null ? t('unknown') : String(history.updates));
    appendDefinition(details, labels[2], String(reference.origins.length));
    byId('run-history-original').textContent = JSON.stringify(reference, null, 2);
}
