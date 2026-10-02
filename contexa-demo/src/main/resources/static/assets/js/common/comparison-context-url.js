export function comparisonContextUrl(path, { parentRunId, historyReportId, journeyStep }) {
    const url = new URL(path, location.origin);
    if (parentRunId) url.searchParams.set('parent', parentRunId);
    if (historyReportId) url.searchParams.set('historyReport', historyReportId);
    if (journeyStep) {
        url.searchParams.set('journey', journeyStep.journeyId);
        url.searchParams.set('step', journeyStep.stepId);
    }
    return `${url.pathname}${url.search}`;
}
