import { escapeHtml } from '../verification-ui-common.js';
import { t } from './prompt-quality-i18n.js';

if (typeof window !== 'undefined' && window.Chart) {
    window.Chart.defaults.color = '#e2e8f0';
    window.Chart.defaults.font.family = "Inter, 'Noto Sans KR', system-ui, sans-serif";
    window.Chart.defaults.font.size = 14;
    window.Chart.defaults.font.weight = '600';
    window.Chart.defaults.borderColor = 'rgba(148, 163, 184, 0.25)';
    window.Chart.defaults.plugins = window.Chart.defaults.plugins || {};
    window.Chart.defaults.plugins.legend = window.Chart.defaults.plugins.legend || {};
    window.Chart.defaults.plugins.legend.labels = Object.assign(window.Chart.defaults.plugins.legend.labels || {}, {
        color: '#e2e8f0',
        boxWidth: 14,
        boxHeight: 14,
        padding: 14,
        font: { size: 14, weight: '700' }
    });
}

export function renderStatusChart(canvas, items, options = {}) {
    renderDoughnut(canvas, items,
            options.title ?? t('enterprise.pqa.common.chart.status.title'),
            options.subtitle ?? t('enterprise.pqa.common.chart.status.subtitle'));
}

export function renderMetricGroupChart(canvas, items, options = {}) {
    renderDoughnut(canvas, items,
            options.title ?? t('enterprise.pqa.common.chart.metricGroup.title'),
            options.subtitle ?? t('enterprise.pqa.common.chart.metricGroup.subtitle'));
}

export function renderIssueRankChart(canvas, items, options = {}) {
    if (!canvas || !window.Chart) {
        return;
    }
    destroyExisting(canvas);
    const safeItems = Array.isArray(items) ? items : [];
    if (!safeItems.length) {
        replaceWithEmpty(canvas, t('enterprise.pqa.common.chart.issue.empty'));
        return;
    }
    const defaultLabel = t('enterprise.pqa.common.chart.issueRank.defaultLabel');
    canvas.__pqaChart = new window.Chart(canvas, {
        type: 'bar',
        data: {
            labels: safeItems.map(item => item.title || item.label || defaultLabel),
            datasets: [{
                label: t('enterprise.pqa.common.chart.issueRank.dataset'),
                data: safeItems.map((item, index) => safeItems.length - index),
                backgroundColor: '#60a5fa',
                borderColor: '#3b82f6',
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: baseOptions(
                options.title ?? t('enterprise.pqa.common.chart.issueRank.title'),
                options.subtitle ?? t('enterprise.pqa.common.chart.issueRank.subtitle'))
    });
}

export function renderComparisonChart(canvas, rows, options = {}) {
    if (!canvas || !window.Chart) {
        return;
    }
    destroyExisting(canvas);
    const safeRows = Array.isArray(rows) ? rows : [];
    if (!safeRows.length) {
        replaceWithEmpty(canvas, t('enterprise.pqa.common.chart.comparison.empty'));
        return;
    }
    canvas.__pqaChart = new window.Chart(canvas, {
        type: 'bar',
        data: {
            labels: safeRows.map(row => row.label),
            datasets: [
                {
                    label: t('enterprise.pqa.common.chart.comparison.before'),
                    data: safeRows.map(row => Number(row.before || 0)),
                    backgroundColor: 'rgba(148, 163, 184, 0.6)',
                    borderColor: '#94a3b8',
                    borderRadius: 6
                },
                {
                    label: t('enterprise.pqa.common.chart.comparison.after'),
                    data: safeRows.map(row => Number(row.after || 0)),
                    backgroundColor: 'rgba(52, 211, 153, 0.7)',
                    borderColor: '#10b981',
                    borderRadius: 6
                }
            ]
        },
        options: baseOptions(
                options.title ?? t('enterprise.pqa.common.chart.comparison.title'),
                options.subtitle ?? t('enterprise.pqa.common.chart.comparison.subtitle'))
    });
}

export function renderLineChart(canvas, rows, title, fields, options = {}) {
    if (!canvas || !window.Chart) {
        return;
    }
    destroyExisting(canvas);
    const safeRows = Array.isArray(rows) ? rows : [];
    if (!safeRows.length) {
        replaceWithEmpty(canvas, t('enterprise.pqa.common.chart.line.empty'));
        return;
    }
    const palette = ['#34d399', '#60a5fa', '#f87171', '#fbbf24', '#a78bfa'];
    const datasets = fields.map((field, index) => ({
        label: field.label,
        data: safeRows.map(row => Number(row[field.key] || 0)),
        borderColor: palette[index % palette.length],
        backgroundColor: 'transparent',
        tension: 0.35,
        borderWidth: 2.5,
        pointRadius: 4,
        pointBackgroundColor: palette[index % palette.length]
    }));
    canvas.__pqaChart = new window.Chart(canvas, {
        type: 'line',
        data: {
            labels: safeRows.map(row => row.label),
            datasets
        },
        options: baseOptions(title, options.subtitle ?? t('enterprise.pqa.common.chart.line.subtitleDefault'))
    });
}

function renderDoughnut(canvas, items, title, subtitle) {
    if (!canvas || !window.Chart) {
        return;
    }
    destroyExisting(canvas);
    const safeItems = Array.isArray(items) ? items : [];
    if (!safeItems.some(item => Number(item.count) > 0)) {
        replaceWithEmpty(canvas, t('enterprise.pqa.common.chart.empty'));
        return;
    }
    canvas.__pqaChart = new window.Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: safeItems.map(item => item.label),
            datasets: [{
                data: safeItems.map(item => Number(item.count || 0)),
                backgroundColor: safeItems.map(item => colorForTone(item.tone))
            }]
        },
        options: baseOptions(title, subtitle)
    });
}

function baseOptions(title, subtitle) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        color: '#e2e8f0',
        scales: {
            x: {
                ticks: { color: '#cbd5e1', font: { size: 13, weight: '600' } },
                grid: { color: 'rgba(148, 163, 184, 0.12)' }
            },
            y: {
                ticks: { color: '#cbd5e1', font: { size: 13, weight: '600' } },
                grid: { color: 'rgba(148, 163, 184, 0.12)' }
            }
        },
        plugins: {
            legend: {
                position: 'bottom',
                labels: {
                    color: '#e2e8f0',
                    padding: 16,
                    boxWidth: 14,
                    boxHeight: 14,
                    font: { size: 14, weight: '700' }
                }
            },
            title: {
                display: true,
                text: title,
                color: '#f8fafc',
                padding: { top: 8, bottom: 4 },
                font: { size: 17, weight: '800' }
            },
            subtitle: {
                display: Boolean(subtitle),
                text: subtitle,
                color: '#94a3b8',
                padding: { bottom: 14 },
                font: { size: 13, weight: '500' }
            },
            tooltip: {
                titleColor: '#f8fafc',
                bodyColor: '#e2e8f0',
                backgroundColor: 'rgba(15, 23, 42, 0.92)',
                borderColor: 'rgba(52, 211, 153, 0.4)',
                borderWidth: 1,
                padding: 12,
                titleFont: { size: 14, weight: '800' },
                bodyFont: { size: 13, weight: '600' },
                callbacks: {
                    label: context => `${context.dataset.label || context.label}: ${context.formattedValue}`
                }
            }
        }
    };
}

function colorForTone(tone) {
    return {
        ready: '#34d399',
        pending: '#fbbf24',
        reverify: '#a78bfa',
        blocked: '#f87171',
        neutral: '#60a5fa'
    }[tone] || '#60a5fa';
}

function replaceWithEmpty(canvas, message) {
    const empty = document.createElement('div');
    empty.className = 'pqa-empty pqa-chart-empty';
    empty.innerHTML = `<p>${escapeHtml(message)}</p>`;
    canvas.replaceWith(empty);
}

function destroyExisting(canvas) {
    if (canvas.__pqaChart) {
        canvas.__pqaChart.destroy();
    }
}
