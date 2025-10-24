document.addEventListener('DOMContentLoaded', () => {
    const wizardContainer = document.getElementById('granting-wizard-container');
    if (!wizardContainer) return;

    const debounce = (func, delay) => {
        let timeout;
        return (...args) => {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), delay);
        };
    };

    const contextId = wizardContainer.dataset.contextId;
    const assignmentType = wizardContainer.dataset.assignmentType;
    const selectionPanel = document.getElementById('selection-panel');
    const assignmentList = document.getElementById('assignment-list');
    const simulationResultContainer = document.getElementById('simulation-result-container');
    const saveButton = document.getElementById('save-button');
    const csrfToken = document.querySelector('meta[name="_csrf"]')?.content;
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]')?.content;
    const allCheckboxes = Array.from(selectionPanel.querySelectorAll('.assignment-checkbox'));
    const initialAssignmentIds = new Set(allCheckboxes.filter(cb => cb.checked).map(cb => cb.value));

    const api = {
        async simulate(changes) {
            return await fetchApi(`/admin/granting-wizard/${contextId}/simulate`, {
                method: 'POST', body: JSON.stringify(changes)
            });
        },
        async commit(changes) {
            return await fetchApi(`/admin/granting-wizard/${contextId}/commit`, {
                method: 'POST', body: JSON.stringify(changes)
            });
        }
    };

    async function fetchApi(url, options = {}) {
        const headers = { 'Content-Type': 'application/json', [csrfHeader]: csrfToken, ...options.headers };
        try {
            const response = await fetch(url, { ...options, headers });
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: `서버 오류 (${response.status})` }));
                throw new Error(errorData.message);
            }
            return response.status === 204 ? null : response.json();
        } catch (error) {
            showToast(error.message, 'error');
            throw error;
        }
    }

    const updateUI = () => {
        updateAssignmentPanel();
        debouncedRunSimulation();
    };

    const debouncedRunSimulation = debounce(runSimulation, 400);

    function getChanges() {
        const currentAssignmentIds = new Set(allCheckboxes.filter(cb => cb.checked).map(cb => cb.value));
        return {
            added: Array.from(currentAssignmentIds).map(id => ({ targetId: Number(id), targetType: assignmentType }))
        };
    }

    async function runSimulation() {
        simulationResultContainer.innerHTML = '<div class="flex items-center justify-center h-full"><i class="fas fa-spinner fa-spin text-3xl text-indigo-400"></i><p class="ml-3">분석 중...</p></div>';
        try {
            const changes = getChanges();
            const result = await api.simulate(changes);
            renderSimulationResult(result);
        } catch (error) {
            simulationResultContainer.innerHTML = `<div class="p-4 text-red-400 bg-red-900/20 rounded-lg">${error.message || '시뮬레이션 중 오류 발생'}</div>`;
        }
    }

    async function handleSave() {
        saveButton.disabled = true;
        saveButton.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>저장 중...';
        try {
            const changes = getChanges();
            await api.commit(changes);
            showToast('성공적으로 저장되었습니다.', 'success');
            setTimeout(() => window.location.href = '/admin/studio', 1500);
        } catch (error) {
            showToast(`저장 실패: ${error.message}`, 'error');
            saveButton.disabled = false;
            saveButton.innerHTML = '<i class="fas fa-save mr-2"></i>저장';
        }
    }

    function updateAssignmentPanel() {
        assignmentList.innerHTML = '';
        const currentIds = new Set(allCheckboxes.filter(cb => cb.checked).map(cb => cb.value));
        const allRelevantIds = new Set([...initialAssignmentIds, ...currentIds]);

        if (allRelevantIds.size === 0) {
            assignmentList.innerHTML = `<div class="text-center text-slate-500 p-8">할당된 항목이 없습니다.</div>`;
            return;
        }

        allRelevantIds.forEach(id => {
            const wasInitial = initialAssignmentIds.has(id);
            const isCurrent = currentIds.has(id);
            const checkbox = document.getElementById('item-' + id);
            if (!checkbox) return;
            const label = document.querySelector(`label[for="item-${id}"]`).textContent;

            let cardHtml = '';
            if (wasInitial && isCurrent) {
                cardHtml = `<div class="p-3 rounded-md flex justify-between items-center bg-slate-700/50"><span class="font-medium">${label}</span><button type="button" data-id="${id}" class="remove-assignment-btn text-slate-400 hover:text-white">×</button></div>`;
            } else if (!wasInitial && isCurrent) {
                cardHtml = `<div class="p-3 rounded-md flex justify-between items-center bg-green-800/30 border border-green-600"><span class="font-medium text-green-300">${label} (추가됨)</span><button type="button" data-id="${id}" class="remove-assignment-btn text-slate-400 hover:text-white">×</button></div>`;
            } else if (wasInitial && !isCurrent) {
                cardHtml = `<div class="p-3 rounded-md flex justify-between items-center bg-red-800/30 border border-red-600"><span class="font-medium line-through text-red-300">${label} (제거됨)</span><button type="button" data-id="${id}" class="restore-assignment-btn text-slate-400 hover:text-white">+</button></div>`;
            }
            if (cardHtml) assignmentList.insertAdjacentHTML('beforeend', cardHtml);
        });
    }

    function renderSimulationResult(result) {
        if (!result) {
            simulationResultContainer.innerHTML = '';
            return;
        }

        // [수정] 전체 HTML 구조를 명확하게 재구성하고, 올바른 문법을 사용합니다.
        let html = `<div class="p-2 bg-slate-800 rounded-md mb-4 text-center text-slate-300 font-semibold">${result.summary}</div>`;

        const gained = result.impactDetails.filter(d => d.impactType === 'PERMISSION_GAINED');
        const lost = result.impactDetails.filter(d => d.impactType === 'PERMISSION_LOST');

        if (gained.length > 0) {
            // 획득할 권한 목록의 HTML 아이템들을 먼저 생성
            const gainedItems = gained.map(d =>
                `<li><span class="math-inline">\{d\.permissionDescription \|\| d\.permissionName\} <span class\="text\-xs text\-slate\-500"\>\(</span>{d.reason})</span></li>`
            ).join('');

            // 생성된 아이템들을 포함하여 전체 섹션의 HTML을 구성
            html += `
            <div>
                <h4 class="font-bold text-green-400 mb-2">
                    <i class="fas fa-plus-circle mr-2"></i>획득할 권한 (${gained.length})
                </h4>
                <ul class="space-y-1 text-sm list-inside text-slate-300">
                    ${gainedItems}
                </ul>
            </div>`;
        }

        if (lost.length > 0) {
            // 상실할 권한 목록의 HTML 아이템들을 먼저 생성
            const lostItems = lost.map(d =>
                `<li>${d.permissionDescription || d.permissionName}</li>`
            ).join('');

            // 생성된 아이템들을 포함하여 전체 섹션의 HTML을 구성
            html += `
            <div class="mt-4">
                <h4 class="font-bold text-red-400 mb-2">
                    <i class="fas fa-minus-circle mr-2"></i>상실할 권한 (${lost.length})
                </h4>
                <ul class="space-y-1 text-sm list-inside text-slate-300">
                    ${lostItems}
                </ul>
            </div>`;
        }

        if (gained.length === 0 && lost.length === 0) {
            html += `<div class="text-center text-slate-500">권한 변경사항이 없습니다.</div>`;
        }

        simulationResultContainer.innerHTML = html;
    }

    selectionPanel.addEventListener('change', (e) => {
        if (e.target.classList.contains('assignment-checkbox')) {
            updateUI();
        }
    });

    assignmentList.addEventListener('click', (e) => {
        const button = e.target.closest('.remove-assignment-btn, .restore-assignment-btn');
        if (!button) return;
        const id = button.dataset.id;
        const checkbox = document.getElementById('item-' + id);
        if (checkbox) {
            checkbox.checked = button.classList.contains('restore-assignment-btn');
            checkbox.dispatchEvent(new Event('change', { bubbles: true }));
        }
    });

    saveButton.addEventListener('click', handleSave);

    updateUI();
});