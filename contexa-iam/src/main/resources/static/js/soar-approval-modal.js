/**
 * SOAR Approval Modal Component
 * 
 * Rich UI modal dialog for tool execution approval
 * Replaces browser confirm with detailed approval interface
 */
class SoarApprovalModal {
    constructor() {
        this.modalContainer = null;
        this.activeModal = null;
        this.approvalQueue = [];
        this.approvalHistory = [];
        this.createStyles();
    }

    /**
     * Create CSS styles for the modal
     */
    createStyles() {
        if (document.getElementById('soar-approval-modal-styles')) return;

        const styles = `
            .soar-approval-modal-overlay {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.8);
                backdrop-filter: blur(10px);
                z-index: 10000;
                display: flex;
                align-items: center;
                justify-content: center;
                animation: fadeIn 0.3s ease-in-out;
            }

            .soar-approval-modal {
                background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
                border-radius: 20px;
                max-width: 600px;
                width: 90%;
                max-height: 80vh;
                overflow: hidden;
                box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
                border: 1px solid rgba(99, 102, 241, 0.3);
                animation: slideUp 0.3s ease-out;
            }

            .soar-approval-header {
                padding: 1.5rem;
                background: linear-gradient(135deg, rgba(99, 102, 241, 0.2) 0%, rgba(139, 92, 246, 0.1) 100%);
                border-bottom: 1px solid rgba(71, 85, 105, 0.3);
            }

            .soar-approval-title {
                font-size: 1.5rem;
                font-weight: 700;
                color: #f1f5f9;
                margin: 0 0 0.5rem 0;
                display: flex;
                align-items: center;
                gap: 0.75rem;
            }

            .soar-approval-subtitle {
                color: #94a3b8;
                font-size: 0.9rem;
            }

            .soar-risk-badge {
                display: inline-flex;
                align-items: center;
                padding: 0.25rem 0.75rem;
                border-radius: 9999px;
                font-size: 0.75rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }

            .soar-risk-critical {
                background: rgba(239, 68, 68, 0.2);
                color: #ef4444;
                border: 1px solid rgba(239, 68, 68, 0.3);
            }

            .soar-risk-high {
                background: rgba(251, 146, 60, 0.2);
                color: #fb923c;
                border: 1px solid rgba(251, 146, 60, 0.3);
            }

            .soar-risk-medium {
                background: rgba(250, 204, 21, 0.2);
                color: #facc15;
                border: 1px solid rgba(250, 204, 21, 0.3);
            }

            .soar-risk-low {
                background: rgba(34, 197, 94, 0.2);
                color: #22c55e;
                border: 1px solid rgba(34, 197, 94, 0.3);
            }

            .soar-approval-body {
                padding: 1.5rem;
                max-height: 50vh;
                overflow-y: auto;
            }

            .soar-approval-section {
                margin-bottom: 1.5rem;
            }

            .soar-approval-section-title {
                color: #cbd5e1;
                font-size: 0.875rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                margin-bottom: 0.5rem;
            }

            .soar-approval-description {
                background: rgba(15, 23, 42, 0.6);
                padding: 1rem;
                border-radius: 0.75rem;
                border: 1px solid rgba(71, 85, 105, 0.3);
                color: #e2e8f0;
                font-size: 0.9rem;
                line-height: 1.6;
            }

            .soar-approval-parameters {
                background: rgba(15, 23, 42, 0.8);
                padding: 1rem;
                border-radius: 0.75rem;
                border: 1px solid rgba(71, 85, 105, 0.3);
                font-family: 'Courier New', monospace;
                font-size: 0.85rem;
                color: #a5f3fc;
                overflow-x: auto;
                white-space: pre-wrap;
                word-wrap: break-word;
            }

            .soar-approval-reason {
                width: 100%;
                background: rgba(15, 23, 42, 0.8);
                border: 1px solid rgba(71, 85, 105, 0.3);
                border-radius: 0.75rem;
                padding: 0.75rem;
                color: #e2e8f0;
                font-size: 0.9rem;
                resize: vertical;
                min-height: 80px;
            }

            .soar-approval-reason:focus {
                outline: none;
                border-color: rgba(99, 102, 241, 0.5);
                box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
            }

            .soar-approval-footer {
                padding: 1.5rem;
                background: rgba(30, 41, 59, 0.5);
                border-top: 1px solid rgba(71, 85, 105, 0.3);
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 1rem;
            }

            .soar-approval-actions {
                display: flex;
                gap: 1rem;
            }

            .soar-approval-btn {
                padding: 0.75rem 1.5rem;
                border-radius: 0.75rem;
                font-weight: 600;
                font-size: 0.9rem;
                cursor: pointer;
                transition: all 0.3s ease;
                border: none;
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
            }

            .soar-approval-btn-approve {
                background: linear-gradient(135deg, #22c55e, #16a34a);
                color: white;
            }

            .soar-approval-btn-approve:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(34, 197, 94, 0.3);
            }

            .soar-approval-btn-reject {
                background: linear-gradient(135deg, #ef4444, #dc2626);
                color: white;
            }

            .soar-approval-btn-reject:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(239, 68, 68, 0.3);
            }

            .soar-approval-btn-later {
                background: rgba(71, 85, 105, 0.3);
                color: #cbd5e1;
                border: 1px solid rgba(71, 85, 105, 0.5);
            }

            .soar-approval-btn-later:hover {
                background: rgba(71, 85, 105, 0.5);
            }

            .soar-approval-queue-indicator {
                display: flex;
                align-items: center;
                gap: 0.5rem;
                color: #94a3b8;
                font-size: 0.875rem;
            }

            .soar-approval-queue-badge {
                background: rgba(99, 102, 241, 0.2);
                color: #a5b4fc;
                padding: 0.25rem 0.5rem;
                border-radius: 0.5rem;
                font-weight: 600;
            }

            .soar-approval-info-grid {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 1rem;
                margin-top: 1rem;
            }

            .soar-approval-info-item {
                background: rgba(30, 41, 59, 0.5);
                padding: 0.75rem;
                border-radius: 0.5rem;
                border: 1px solid rgba(71, 85, 105, 0.3);
            }

            .soar-approval-info-label {
                color: #94a3b8;
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                margin-bottom: 0.25rem;
            }

            .soar-approval-info-value {
                color: #e2e8f0;
                font-size: 0.9rem;
                font-weight: 600;
            }

            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }

            @keyframes slideUp {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
        `;

        const styleSheet = document.createElement('style');
        styleSheet.id = 'soar-approval-modal-styles';
        styleSheet.textContent = styles;
        document.head.appendChild(styleSheet);
    }

    /**
     * Show approval modal
     */
    show(approvalRequest) {
        console.log('🔔 SoarApprovalModal.show() called with:', approvalRequest);
        
        return new Promise((resolve) => {
            // Add to queue if modal is already active
            if (this.activeModal) {
                console.log('⏳ Modal already active, adding to queue');
                this.approvalQueue.push({ request: approvalRequest, resolve });
                this.updateQueueIndicator();
                return;
            }

            console.log('Creating modal HTML...');
            const modalHtml = this.createModalHtml(approvalRequest);
            const overlay = document.createElement('div');
            overlay.className = 'soar-approval-modal-overlay';
            overlay.innerHTML = modalHtml;

            console.log('📌 Appending modal to document body...');
            document.body.appendChild(overlay);
            this.activeModal = overlay;
            
            console.log('Modal displayed successfully!');
            console.log('🎯 Modal element:', overlay);

            // Bind event handlers
            this.bindEventHandlers(approvalRequest, resolve);
            
            // Focus on reason textarea
            const reasonTextarea = overlay.querySelector('.soar-approval-reason');
            if (reasonTextarea) {
                reasonTextarea.focus();
                console.log('Focus set on reason textarea');
            }
            
            // 시각적 알림을 위한 배경색 깜빡임 효과
            const originalBodyStyle = document.body.style.backgroundColor;
            document.body.style.backgroundColor = 'rgba(99, 102, 241, 0.1)';
            setTimeout(() => {
                document.body.style.backgroundColor = originalBodyStyle;
            }, 300);
        });
    }

    /**
     * Create modal HTML
     */
    createModalHtml(request) {
        const riskClass = this.getRiskClass(request.riskLevel);
        const riskLabel = this.getRiskLabel(request.riskLevel);
        const parametersJson = this.formatParameters(request.parameters);

        return `
            <div class="soar-approval-modal">
                <div class="soar-approval-header">
                    <h3 class="soar-approval-title">
                        <i class="fas fa-shield-alt"></i>
                        도구 실행 승인 요청
                        <span class="soar-risk-badge ${riskClass}">${riskLabel}</span>
                    </h3>
                    <div class="soar-approval-subtitle">
                        보안 작업을 실행하기 전에 승인이 필요합니다
                    </div>
                </div>

                <div class="soar-approval-body">
                    <div class="soar-approval-section">
                        <div class="soar-approval-section-title">도구 정보</div>
                        <div class="soar-approval-info-grid">
                            <div class="soar-approval-info-item">
                                <div class="soar-approval-info-label">도구 이름</div>
                                <div class="soar-approval-info-value">${request.toolName}</div>
                            </div>
                            <div class="soar-approval-info-item">
                                <div class="soar-approval-info-label">세션 ID</div>
                                <div class="soar-approval-info-value">${request.sessionId || 'N/A'}</div>
                            </div>
                            <div class="soar-approval-info-item">
                                <div class="soar-approval-info-label">타임스탬프</div>
                                <div class="soar-approval-info-value">${new Date().toLocaleTimeString()}</div>
                            </div>
                            <div class="soar-approval-info-item">
                                <div class="soar-approval-info-label">승인 ID</div>
                                <div class="soar-approval-info-value">${request.approvalId || request.toolName}</div>
                            </div>
                        </div>
                    </div>

                    <div class="soar-approval-section">
                        <div class="soar-approval-section-title">작업 설명</div>
                        <div class="soar-approval-description">
                            ${request.description || '이 도구는 보안 관련 작업을 수행합니다.'}
                        </div>
                    </div>

                    ${parametersJson ? `
                    <div class="soar-approval-section">
                        <div class="soar-approval-section-title">실행 매개변수</div>
                        <div class="soar-approval-parameters">${parametersJson}</div>
                    </div>
                    ` : ''}

                    <div class="soar-approval-section">
                        <div class="soar-approval-section-title">승인 이유 (선택사항)</div>
                        <textarea class="soar-approval-reason" 
                                  placeholder="승인 또는 거부 이유를 입력하세요..."></textarea>
                    </div>
                </div>

                <div class="soar-approval-footer">
                    <div class="soar-approval-queue-indicator">
                        ${this.approvalQueue.length > 0 ? `
                            <span>대기 중인 승인:</span>
                            <span class="soar-approval-queue-badge">${this.approvalQueue.length}</span>
                        ` : ''}
                    </div>
                    <div class="soar-approval-actions">
                        <button class="soar-approval-btn soar-approval-btn-later" data-action="later">
                            <i class="fas fa-clock"></i> 나중에
                        </button>
                        <button class="soar-approval-btn soar-approval-btn-reject" data-action="reject">
                            <i class="fas fa-times"></i> 거부
                        </button>
                        <button class="soar-approval-btn soar-approval-btn-approve" data-action="approve">
                            <i class="fas fa-check"></i> 승인
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Bind event handlers
     */
    bindEventHandlers(request, resolve) {
        const modal = this.activeModal;
        const buttons = modal.querySelectorAll('.soar-approval-btn');
        const reasonTextarea = modal.querySelector('.soar-approval-reason');

        buttons.forEach(button => {
            button.addEventListener('click', (e) => {
                const action = e.currentTarget.dataset.action;
                const reason = reasonTextarea ? reasonTextarea.value : '';

                if (action === 'approve') {
                    this.handleApproval(request, true, reason, resolve);
                } else if (action === 'reject') {
                    this.handleApproval(request, false, reason, resolve);
                } else if (action === 'later') {
                    this.handleLater(request, resolve);
                }
            });
        });

        // Handle ESC key
        const handleEsc = (e) => {
            if (e.key === 'Escape') {
                this.handleLater(request, resolve);
                document.removeEventListener('keydown', handleEsc);
            }
        };
        document.addEventListener('keydown', handleEsc);

        // Handle click outside
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.handleLater(request, resolve);
            }
        });
    }

    /**
     * Handle approval decision
     */
    handleApproval(request, approved, reason, resolve) {
        // Add to history
        this.approvalHistory.push({
            ...request,
            approved,
            reason,
            timestamp: new Date().toISOString()
        });

        // Close modal
        this.closeModal();

        // Resolve with decision
        resolve({
            approved,
            reason: reason || (approved ? 'User approved' : 'User rejected'),
            timestamp: new Date().toISOString()
        });

        // Process next in queue
        this.processQueue();
    }

    /**
     * Handle "Later" action
     */
    handleLater(request, resolve) {
        // Add back to queue
        this.approvalQueue.push({ request, resolve });
        
        // Close modal
        this.closeModal();

        // Process next in queue if any
        this.processQueue();
    }

    /**
     * Close current modal
     */
    closeModal() {
        if (this.activeModal) {
            this.activeModal.remove();
            this.activeModal = null;
        }
    }

    /**
     * Process approval queue
     */
    processQueue() {
        if (this.approvalQueue.length > 0 && !this.activeModal) {
            const next = this.approvalQueue.shift();
            this.show(next.request).then(next.resolve);
        }
    }

    /**
     * Update queue indicator
     */
    updateQueueIndicator() {
        if (this.activeModal) {
            const indicator = this.activeModal.querySelector('.soar-approval-queue-indicator');
            if (indicator) {
                indicator.innerHTML = `
                    <span>대기 중인 승인:</span>
                    <span class="soar-approval-queue-badge">${this.approvalQueue.length}</span>
                `;
            }
        }
    }

    /**
     * Get risk class for styling
     */
    getRiskClass(riskLevel) {
        const level = (riskLevel || 'medium').toLowerCase();
        return `soar-risk-${level}`;
    }

    /**
     * Get risk label
     */
    getRiskLabel(riskLevel) {
        const labels = {
            critical: '위험',
            high: '높음',
            medium: '보통',
            low: '낮음'
        };
        return labels[(riskLevel || 'medium').toLowerCase()] || '보통';
    }

    /**
     * Format parameters for display
     */
    formatParameters(parameters) {
        if (!parameters) return null;
        
        try {
            if (typeof parameters === 'string') {
                return parameters;
            }
            return JSON.stringify(parameters, null, 2);
        } catch (error) {
            return String(parameters);
        }
    }

    /**
     * Get approval history
     */
    getHistory() {
        return this.approvalHistory;
    }

    /**
     * Clear approval history
     */
    clearHistory() {
        this.approvalHistory = [];
    }

    /**
     * Get queue size
     */
    getQueueSize() {
        return this.approvalQueue.length;
    }

    /**
     * Check if modal is currently open
     * @returns {boolean} True if modal is active, false otherwise
     */
    isOpen() {
        return this.activeModal !== null && this.activeModal !== undefined;
    }

    /**
     * Get current approval ID from active modal
     * @returns {string|null} The approval ID or null if no modal is active
     */
    getCurrentApprovalId() {
        if (!this.isOpen()) {
            return null;
        }

        // Try multiple selectors to find the approval ID
        const selectors = [
            '.soar-approval-info-value:last-child', // 승인 ID는 마지막 정보 항목
            '[data-approval-id]', // data attribute
            '.approval-id' // class selector
        ];

        for (const selector of selectors) {
            const element = this.activeModal.querySelector(selector);
            if (element) {
                const approvalId = element.getAttribute('data-approval-id') || element.textContent;
                if (approvalId && approvalId !== 'N/A') {
                    return approvalId.trim();
                }
            }
        }

        // Fallback: parse from modal content
        const infoItems = this.activeModal.querySelectorAll('.soar-approval-info-item');
        for (const item of infoItems) {
            const label = item.querySelector('.soar-approval-info-label');
            if (label && label.textContent.includes('승인 ID')) {
                const value = item.querySelector('.soar-approval-info-value');
                return value ? value.textContent.trim() : null;
            }
        }

        return null;
    }

    /**
     * Close modal (alias for closeModal for compatibility)
     * @param {boolean} force - Force close without processing queue
     */
    close(force = false) {
        this.closeModal();
        
        // Process queue unless force close
        if (!force) {
            this.processQueue();
        }
    }

    /**
     * Get current modal state
     * @returns {Object} Current modal state information
     */
    getModalState() {
        return {
            isOpen: this.isOpen(),
            currentApprovalId: this.getCurrentApprovalId(),
            queueSize: this.getQueueSize(),
            historyCount: this.approvalHistory.length
        };
    }

    /**
     * Set current approval ID (for tracking purposes)
     * @param {string} approvalId - The approval ID to set
     */
    setCurrentApprovalId(approvalId) {
        if (this.activeModal && approvalId) {
            // Store approval ID as data attribute
            this.activeModal.setAttribute('data-current-approval-id', approvalId);
            
            // Also update the display if possible
            const approvalIdElements = this.activeModal.querySelectorAll('.soar-approval-info-value');
            const lastElement = approvalIdElements[approvalIdElements.length - 1];
            if (lastElement) {
                lastElement.setAttribute('data-approval-id', approvalId);
            }
        }
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SoarApprovalModal;
}

// Make available globally for browser environment
if (typeof window !== 'undefined') {
    window.SoarApprovalModal = SoarApprovalModal;
}