/**
 * AI Policy Approval Management JavaScript
 *
 * AI 정책 승인 관리를 위한 클라이언트 사이드 로직
 *
 * @author contexa
 * @since 3.1.0
 */

// 전역 변수
let currentPage = 0;
let totalPages = 0;
let selectedPolicies = new Set();
let currentPolicyId = null;
let autoRefreshInterval = null;

// 페이지 로드 시 초기화
document.addEventListener('DOMContentLoaded', function() {
    loadStatistics();
    loadPolicies();

    // 자동 새로고침 토글
    document.getElementById('autoRefresh').addEventListener('change', function(e) {
        if (e.target.checked) {
            autoRefreshInterval = setInterval(() => {
                loadStatistics();
                loadPolicies();
            }, 10000);
        } else {
            clearInterval(autoRefreshInterval);
        }
    });

    // 필터 변경 이벤트
    document.getElementById('sourceFilter').addEventListener('change', loadPolicies);
    document.getElementById('statusFilter').addEventListener('change', loadPolicies);
});

/**
 * 통계 데이터 로드
 */
async function loadStatistics() {
    try {
        const response = await axios.get('/api/ai/policies/statistics');
        const stats = response.data;

        document.getElementById('totalPolicies').textContent = stats.total || 0;
        document.getElementById('pendingPolicies').textContent = stats.byStatus?.PENDING || 0;
        document.getElementById('approvalRate').textContent =
            (stats.approvalRate || 0).toFixed(1) + '%';
        document.getElementById('avgConfidence').textContent =
            (stats.avgConfidenceScore || 0).toFixed(2);

    } catch (error) {
        console.error('통계 로드 실패:', error);
        showAlert('통계 데이터를 불러오는데 실패했습니다.', 'danger');
    }
}

/**
 * 정책 목록 로드
 */
async function loadPolicies(page = 0) {
    try {
        const source = document.getElementById('sourceFilter').value;
        const status = document.getElementById('statusFilter').value;

        const params = {
            page: page,
            size: 10,
            sort: 'createdAt,desc'
        };

        if (source) params.source = source;
        if (status) params.status = status;

        const response = await axios.get('/api/ai/policies', { params });
        const data = response.data;

        currentPage = data.number;
        totalPages = data.totalPages;

        renderPolicyRows(data.content);
        renderPagination();

    } catch (error) {
        console.error('정책 로드 실패:', error);
        showAlert('정책 목록을 불러오는데 실패했습니다.', 'danger');
    }
}


/**
 * 정책 테이블 행 렌더링
 */
function renderPolicyRows(policies) {
    const tbody = document.getElementById('policyTableBody');
    tbody.innerHTML = '';

    if (policies.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="py-4 px-6 text-center" style="color: #94a3b8;">
                    표시할 정책이 없습니다.
                </td>
            </tr>
        `;
        return;
    }

    policies.forEach(policy => {
        const row = createPolicyRow(policy);
        tbody.appendChild(row);
    });
}

/**
 * 정책 테이블 행 생성
 */
function createPolicyRow(policy) {
    const tr = document.createElement('tr');
    tr.style.borderColor = 'rgba(71, 85, 105, 0.3)';

    const confidenceBar = policy.confidenceScore ? `
        <div class="w-full bg-gray-700 rounded-full h-2 mt-1">
            <div class="h-2 rounded-full" style="width: ${policy.confidenceScore * 100}%; background: ${getConfidenceColor(policy.confidenceScore)};"></div>
        </div>
        <span class="text-xs" style="color: #94a3b8;">${(policy.confidenceScore * 100).toFixed(0)}%</span>
    ` : '<span style="color: #94a3b8;">-</span>';

    tr.innerHTML = `
        <td class="py-4 px-6">
            ${policy.approvalStatus === 'PENDING' ? `
                <input type="checkbox" value="${policy.id}"
                       onchange="togglePolicySelection(${policy.id})"
                       class="rounded">
            ` : ''}
        </td>
        <td class="py-4 px-6">
            <p class="font-medium">${escapeHtml(policy.name)}</p>
            <p style="color: #94a3b8;" class="text-sm">${escapeHtml(policy.description || '')}</p>
        </td>
        <td class="py-4 px-6">
            <span class="font-bold text-xs p-1 rounded"
                  style="background: rgba(99, 102, 241, 0.2); color: #818cf8;">
                ${policy.source === 'AI_GENERATED' ? 'AI 생성' : 'AI 진화'}
            </span>
            ${policy.aiModel ? `
                <br><span class="text-xs" style="color: #94a3b8;">${policy.aiModel}</span>
            ` : ''}
        </td>
        <td class="py-4 px-6">
            ${confidenceBar}
        </td>
        <td class="py-4 px-6">
            ${getStatusBadge(policy.approvalStatus)}
        </td>
        <td class="py-4 px-6 text-sm" style="color: #cbd5e1;">
            ${new Date(policy.createdAt).toLocaleDateString('ko-KR')}
        </td>
        <td class="py-4 px-6">
            <div class="flex gap-1">
                ${policy.approvalStatus === 'PENDING' ? `
                    <button onclick="approvePolicy(${policy.id})"
                            class="px-2 py-1 rounded-md text-sm font-medium transition-all duration-300"
                            style="background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3);"
                            title="승인">
                        <i class="bi bi-check-circle"></i>
                    </button>
                    <button onclick="rejectPolicy(${policy.id})"
                            class="px-2 py-1 rounded-md text-sm font-medium transition-all duration-300"
                            style="background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3);"
                            title="거부">
                        <i class="bi bi-x-circle"></i>
                    </button>
                ` : ''}
                <button onclick="showPolicyDetail(${policy.id})"
                        class="px-2 py-1 rounded-md text-sm font-medium transition-all duration-300"
                        style="background: rgba(99, 102, 241, 0.2); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.3);"
                        title="상세">
                    <i class="bi bi-eye"></i>
                </button>
            </div>
        </td>
    `;

    return tr;
}

/**
 * 정책 상세 정보 표시
 */
async function showPolicyDetail(policyId) {
    try {
        const response = await axios.get(`/api/ai/policies/${policyId}`);
        const policy = response.data;

        currentPolicyId = policyId;

        const content = document.getElementById('policyDetailContent');
        content.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <h6>기본 정보</h6>
                    <dl>
                        <dt>이름</dt>
                        <dd>${escapeHtml(policy.name)}</dd>

                        <dt>설명</dt>
                        <dd>${escapeHtml(policy.description || '없음')}</dd>

                        <dt>친화적 설명</dt>
                        <dd>${escapeHtml(policy.friendlyDescription || '없음')}</dd>

                        <dt>효과</dt>
                        <dd><span class="badge bg-${policy.effect === 'PERMIT' ? 'success' : 'danger'}">
                            ${policy.effect}
                        </span></dd>

                        <dt>우선순위</dt>
                        <dd>${policy.priority}</dd>
                    </dl>
                </div>

                <div class="col-md-6">
                    <h6>AI 정보</h6>
                    <dl>
                        <dt>출처</dt>
                        <dd>${policy.source}</dd>

                        <dt>AI 모델</dt>
                        <dd>${policy.aiModel || '알 수 없음'}</dd>

                        <dt>신뢰도 점수</dt>
                        <dd>${policy.confidenceScore ?
                            (policy.confidenceScore * 100).toFixed(1) + '%' : 'N/A'}</dd>

                        <dt>상태</dt>
                        <dd>${getStatusBadge(policy.approvalStatus)}</dd>

                        <dt>활성 상태</dt>
                        <dd>${policy.isActive ?
                            '<span class="badge bg-success">활성</span>' :
                            '<span class="badge bg-secondary">비활성</span>'}</dd>
                    </dl>
                </div>
            </div>

            ${policy.targets && policy.targets.length > 0 ? `
                <div class="mt-3">
                    <h6>대상</h6>
                    <ul class="list-group">
                        ${policy.targets.map(target =>
                            `<li class="list-group-item">${escapeHtml(target)}</li>`
                        ).join('')}
                    </ul>
                </div>
            ` : ''}

            ${policy.rules && policy.rules.length > 0 ? `
                <div class="mt-3">
                    <h6>규칙</h6>
                    <pre>${escapeHtml(JSON.stringify(policy.rules, null, 2))}</pre>
                </div>
            ` : ''}

            ${policy.approvedBy ? `
                <div class="mt-3">
                    <small class="text-muted">
                        승인자: ${policy.approvedBy}
                        (${new Date(policy.approvedAt).toLocaleString('ko-KR')})
                    </small>
                </div>
            ` : ''}
        `;

        // 모달 버튼 상태 업데이트
        const approveBtn = document.getElementById('modalApproveBtn');
        const rejectBtn = document.getElementById('modalRejectBtn');

        if (policy.approvalStatus === 'PENDING') {
            approveBtn.style.display = 'inline-block';
            rejectBtn.style.display = 'inline-block';
            approveBtn.onclick = () => approvePolicy(policyId);
            rejectBtn.onclick = () => rejectPolicy(policyId);
        } else {
            approveBtn.style.display = 'none';
            rejectBtn.style.display = 'none';
        }

        // 모달 표시
        const modal = new bootstrap.Modal(document.getElementById('policyDetailModal'));
        modal.show();

    } catch (error) {
        console.error('정책 상세 정보 로드 실패:', error);
        showAlert('정책 상세 정보를 불러오는데 실패했습니다.', 'danger');
    }
}

/**
 * 정책 승인
 */
async function approvePolicy(policyId) {
    try {
        const response = await axios.post(`/api/ai/policies/${policyId}/approve`, {
            activateImmediately: true
        });

        if (response.data.success) {
            showAlert('정책이 승인되었습니다.', 'success');
            loadStatistics();
            loadPolicies(currentPage);

            // 모달 닫기
            const modal = bootstrap.Modal.getInstance(document.getElementById('policyDetailModal'));
            if (modal) modal.hide();
        } else {
            showAlert(response.data.message || '승인에 실패했습니다.', 'danger');
        }

    } catch (error) {
        console.error('정책 승인 실패:', error);
        showAlert('정책 승인에 실패했습니다.', 'danger');
    }
}

/**
 * 정책 거부
 */
function rejectPolicy(policyId) {
    currentPolicyId = policyId;

    // 상세 모달 닫기
    const detailModal = bootstrap.Modal.getInstance(document.getElementById('policyDetailModal'));
    if (detailModal) detailModal.hide();

    // 거부 사유 모달 열기
    const rejectModal = new bootstrap.Modal(document.getElementById('rejectReasonModal'));
    rejectModal.show();
}

/**
 * 거부 확인
 */
async function confirmReject() {
    const reason = document.getElementById('rejectReason').value.trim();

    if (!reason) {
        showAlert('거부 사유를 입력해주세요.', 'warning');
        return;
    }

    try {
        const response = await axios.post(`/api/ai/policies/${currentPolicyId}/reject`, {
            reason: reason
        });

        if (response.data.success) {
            showAlert('정책이 거부되었습니다.', 'success');
            loadStatistics();
            loadPolicies(currentPage);

            // 모달 닫기
            const modal = bootstrap.Modal.getInstance(document.getElementById('rejectReasonModal'));
            modal.hide();

            // 입력 필드 초기화
            document.getElementById('rejectReason').value = '';
        } else {
            showAlert(response.data.message || '거부에 실패했습니다.', 'danger');
        }

    } catch (error) {
        console.error('정책 거부 실패:', error);
        showAlert('정책 거부에 실패했습니다.', 'danger');
    }
}

/**
 * 정책 선택 토글
 */
function togglePolicySelection(policyId) {
    if (selectedPolicies.has(policyId)) {
        selectedPolicies.delete(policyId);
    } else {
        selectedPolicies.add(policyId);
    }

    // 일괄 승인 버튼 활성화/비활성화
    document.getElementById('batchApproveBtn').disabled = selectedPolicies.size === 0;
}

/**
 * 일괄 승인
 */
async function batchApprove() {
    if (selectedPolicies.size === 0) {
        showAlert('승인할 정책을 선택해주세요.', 'warning');
        return;
    }

    if (!confirm(`선택한 ${selectedPolicies.size}개의 정책을 모두 승인하시겠습니까?`)) {
        return;
    }

    try {
        const response = await axios.post('/api/ai/policies/batch/approve', {
            policyIds: Array.from(selectedPolicies),
            activateImmediately: true
        });

        const result = response.data;
        const message = `승인 완료: ${result.successCount}개, ` +
                       `실패: ${result.failedCount}개, ` +
                       `건너뜀: ${result.skippedCount}개`;

        showAlert(message, result.failedCount > 0 ? 'warning' : 'success');

        // 선택 초기화
        selectedPolicies.clear();
        document.getElementById('batchApproveBtn').disabled = true;

        // 목록 새로고침
        loadStatistics();
        loadPolicies(currentPage);

    } catch (error) {
        console.error('일괄 승인 실패:', error);
        showAlert('일괄 승인에 실패했습니다.', 'danger');
    }
}

/**
 * 페이지네이션 렌더링
 */
function renderPagination() {
    const pagination = document.getElementById('pagination');
    pagination.innerHTML = '';

    if (totalPages <= 1) return;

    // 이전 버튼
    const prevLi = document.createElement('li');
    prevLi.className = `page-item ${currentPage === 0 ? 'disabled' : ''}`;
    prevLi.innerHTML = `
        <a class="page-link" href="#" onclick="loadPolicies(${currentPage - 1}); return false;">
            이전
        </a>
    `;
    pagination.appendChild(prevLi);

    // 페이지 번호
    const startPage = Math.max(0, currentPage - 2);
    const endPage = Math.min(totalPages - 1, currentPage + 2);

    for (let i = startPage; i <= endPage; i++) {
        const li = document.createElement('li');
        li.className = `page-item ${i === currentPage ? 'active' : ''}`;
        li.innerHTML = `
            <a class="page-link" href="#" onclick="loadPolicies(${i}); return false;">
                ${i + 1}
            </a>
        `;
        pagination.appendChild(li);
    }

    // 다음 버튼
    const nextLi = document.createElement('li');
    nextLi.className = `page-item ${currentPage === totalPages - 1 ? 'disabled' : ''}`;
    nextLi.innerHTML = `
        <a class="page-link" href="#" onclick="loadPolicies(${currentPage + 1}); return false;">
            다음
        </a>
    `;
    pagination.appendChild(nextLi);
}

/**
 * 신뢰도 점수에 따른 CSS 클래스 반환
 */
function getConfidenceClass(score) {
    if (!score) return '';
    if (score >= 0.8) return 'high-confidence';
    if (score >= 0.5) return 'medium-confidence';
    return 'low-confidence';
}

/**
 * 상태 배지 생성
 */
function getStatusBadge(status) {
    const badges = {
        'PENDING': '<span class="badge bg-warning">승인 대기</span>',
        'APPROVED': '<span class="badge bg-success">승인됨</span>',
        'REJECTED': '<span class="badge bg-danger">거부됨</span>'
    };
    return badges[status] || '<span class="badge bg-secondary">알 수 없음</span>';
}

/**
 * 알림 표시
 */
function showAlert(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container');
    const toastId = 'toast-' + Date.now();

    const bgColor = {
        'success': 'rgba(34, 197, 94, 0.9)',
        'danger': 'rgba(239, 68, 68, 0.9)',
        'warning': 'rgba(251, 191, 36, 0.9)',
        'info': 'rgba(99, 102, 241, 0.9)'
    }[type] || 'rgba(99, 102, 241, 0.9)';

    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = 'mb-2 p-4 rounded-lg shadow-lg text-white';
    toast.style.background = bgColor;
    toast.innerHTML = `
        <div class="flex justify-between items-center">
            <span>${message}</span>
            <button onclick="document.getElementById('${toastId}').remove()" class="ml-4 text-white hover:text-gray-200">
                <i class="bi bi-x-lg"></i>
            </button>
        </div>
    `;

    toastContainer.appendChild(toast);

    // 5초 후 자동 제거
    setTimeout(() => {
        const element = document.getElementById(toastId);
        if (element) element.remove();
    }, 5000);
}

/**
 * 모달 닫기 함수들
 */
function closePolicyDetailModal() {
    document.getElementById('policyDetailModal').classList.add('hidden');
    document.getElementById('policyDetailModal').classList.remove('flex');
}

function closeRejectReasonModal() {
    document.getElementById('rejectReasonModal').classList.add('hidden');
    document.getElementById('rejectReasonModal').classList.remove('flex');
    document.getElementById('rejectReason').value = '';
}

function approvePolicyFromModal() {
    if (currentPolicyId) {
        approvePolicy(currentPolicyId);
    }
}

function rejectPolicyFromModal() {
    if (currentPolicyId) {
        rejectPolicy(currentPolicyId);
    }
}

/**
 * HTML 이스케이프
 */
function escapeHtml(text) {
    if (!text) return '';
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}