// src/main/resources/static/js/studio.js (신규 파일)
document.addEventListener('DOMContentLoaded', async () => {
    let metadata = {};

    async function initializeForm() {
        try {
            const response = await fetch('/api/admin/authoring/metadata');
            if (!response.ok) throw new Error('메타데이터 로드 실패');
            metadata = await response.json();

            $('#subjectUserIds').select2({
                placeholder: '사용자를 선택하세요 (선택 사항)', allowClear: true,
                data: metadata.subjects.users.map(u => ({ id: u.id, text: `${u.name} (${u.username})` }))
            });
            $('#subjectGroupIds').select2({
                placeholder: '그룹을 선택하세요 (선택 사항)', allowClear: true,
                data: metadata.subjects.groups.map(g => ({ id: g.id, text: g.name }))
            });
            $('#businessResourceId').select2({
                placeholder: '자원을 선택하세요', allowClear: true,
                data: [{id: '', text: ''}].concat(metadata.resources.map(r => ({ id: r.id, text: r.name })))
            });
            $('#businessActionId').select2({
                placeholder: '행위를 선택하세요', allowClear: true,
                data: [{id: '', text: ''}].concat(metadata.actions.map(a => ({ id: a.id, text: a.name })))
            });
        } catch (error) { showToast(error.message, 'error'); }
    }

    document.getElementById('add-condition-btn').addEventListener('click', () => {
        const container = document.getElementById('condition-container');
        const conditionIndex = container.children.length;
        const templateIdName = `conditions[${conditionIndex}].templateId`;
        const paramsName = `conditions[${conditionIndex}].params`;

        const conditionHtml = `
            <div class="condition-item grid grid-cols-12 gap-4 items-center p-3 border border-slate-700 rounded-lg bg-slate-800">
                <div class="col-span-5">
                    <select class="condition-template-select form-input-dark" name="${templateIdName}">
                        <option value="">조건 유형 선택</option>
                        ${metadata.conditionTemplates.map(t => `<option value="${t.id}" data-params="${t.parameterCount}">${t.name}</option>`).join('')}
                    </select>
                </div>
                <div class="col-span-6 condition-params-container" data-param-name="${paramsName}"></div>
                <div class="col-span-1 text-center">
                    <button type="button" class="text-red-500 hover:text-red-400 remove-condition-btn text-2xl font-bold">&times;</button>
                </div>
            </div>`;
        container.insertAdjacentHTML('beforeend', conditionHtml);
    });

    document.getElementById('condition-container').addEventListener('change', e => {
        if (e.target.classList.contains('condition-template-select')) {
            const selectedOption = e.target.options[e.target.selectedIndex];
            const paramCount = parseInt(selectedOption.dataset.params || '0', 10);
            const paramsContainer = e.target.closest('.condition-item').querySelector('.condition-params-container');
            const paramName = paramsContainer.dataset.paramName;
            paramsContainer.innerHTML = '';
            for (let i = 0; i < paramCount; i++) {
                paramsContainer.innerHTML += `<input type="text" class="form-input-dark mt-1" name="${paramName}" placeholder="파라미터 ${i + 1} 입력" required>`;
            }
        }
    });

    document.getElementById('condition-container').addEventListener('click', e => {
        if (e.target.classList.contains('remove-condition-btn')) {
            e.target.closest('.condition-item').remove();
        }
    });

    initializeForm();
});