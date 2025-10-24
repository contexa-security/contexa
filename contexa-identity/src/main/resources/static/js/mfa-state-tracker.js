// static/js/mfa-state-tracker.js
class MfaStateTracker {
    constructor() {
        this.currentState = null;
        this.sessionId = null;
        this.stateMetadata = {};
        this.transitions = [];
        this.lastUpdate = null;
    }

    updateFromServerResponse(response) {
        if (!response.stateMachine) return;

        const sm = response.stateMachine;
        const previousState = this.currentState;

        this.currentState = sm.currentState;
        this.sessionId = sm.sessionId || this.sessionId;
        this.stateMetadata = sm.stateMetadata || {};
        this.lastUpdate = new Date();

        // 전이 기록
        if (previousState && previousState !== this.currentState) {
            this.transitions.push({
                from: previousState,
                to: this.currentState,
                timestamp: this.lastUpdate,
                event: sm.lastEvent
            });
        }

        // 세션 스토리지에 저장
        this.saveToSession();

        console.log(`[State Machine] State updated: ${previousState} -> ${this.currentState}`);
    }

    canTransitionTo(targetState) {
        // 서버의 MfaStateMachineConfiguration과 완전히 일치
        const validTransitions = {
            'NONE': ['PRIMARY_AUTHENTICATION_COMPLETED'],
            'PRIMARY_AUTHENTICATION_COMPLETED': ['MFA_NOT_REQUIRED', 'AWAITING_FACTOR_SELECTION', 'MFA_CONFIGURATION_REQUIRED', 'MFA_REQUIRED_SELECT_FACTOR', 'MFA_SYSTEM_ERROR'],
            'AWAITING_FACTOR_SELECTION': ['AWAITING_FACTOR_CHALLENGE_INITIATION', 'MFA_CANCELLED', 'MFA_SESSION_EXPIRED', 'MFA_SYSTEM_ERROR'],
            'AWAITING_FACTOR_CHALLENGE_INITIATION': ['FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION', 'MFA_CANCELLED', 'MFA_SESSION_EXPIRED'],
            'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION': ['FACTOR_VERIFICATION_PENDING', 'MFA_CANCELLED', 'MFA_SESSION_EXPIRED', 'AWAITING_FACTOR_SELECTION'],
            'FACTOR_VERIFICATION_PENDING': ['FACTOR_VERIFICATION_COMPLETED', 'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION', 'MFA_RETRY_LIMIT_EXCEEDED', 'MFA_SYSTEM_ERROR'],
            'FACTOR_VERIFICATION_COMPLETED': ['ALL_FACTORS_COMPLETED', 'AWAITING_FACTOR_SELECTION'],
            'ALL_FACTORS_COMPLETED': ['MFA_SUCCESSFUL'],
            'MFA_RETRY_LIMIT_EXCEEDED': ['MFA_FAILED_TERMINAL']
        };

        const allowed = validTransitions[this.currentState] || [];
        return allowed.includes(targetState);
    }

    isTerminalState() {
        // 서버의 configure states와 일치
        const terminalStates = [
            'MFA_SUCCESSFUL',
            'MFA_NOT_REQUIRED',
            'MFA_FAILED_TERMINAL',
            'MFA_CANCELLED',
            'MFA_SESSION_EXPIRED',
            'MFA_SYSTEM_ERROR',
            'MFA_SESSION_INVALIDATED',
            'MFA_CONFIGURATION_REQUIRED' // 추가
        ];
        return terminalStates.includes(this.currentState);
    }

    isWaitingForUserAction() {
        // 서버 로직과 일치
        return this.currentState === 'AWAITING_FACTOR_SELECTION' ||
            this.currentState === 'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION' ||
            this.currentState === 'MFA_CONFIGURATION_REQUIRED'; // 추가
    }

    isProcessing() {
        // 서버 로직과 일치
        return this.currentState === 'AWAITING_FACTOR_CHALLENGE_INITIATION' ||
            this.currentState === 'FACTOR_VERIFICATION_PENDING' ||
            this.currentState === 'PRIMARY_AUTHENTICATION_COMPLETED'; // 추가
    }

    isValid() {
        return this.currentState && this.sessionId &&
            (new Date() - this.lastUpdate) < 30 * 60 * 1000; // 30분
    }

    saveToSession() {
        sessionStorage.setItem('mfaStateTracker', JSON.stringify({
            currentState: this.currentState,
            sessionId: this.sessionId,
            stateMetadata: this.stateMetadata,
            transitions: this.transitions,
            lastUpdate: this.lastUpdate
        }));
    }

    restoreFromSession() {
        const stored = sessionStorage.getItem('mfaStateTracker');
        if (stored) {
            try {
                const data = JSON.parse(stored);
                Object.assign(this, data);
                this.lastUpdate = new Date(data.lastUpdate);
                console.log(`[State Machine] Restored state: ${this.currentState}`);
            } catch (e) {
                console.error('[State Machine] Failed to restore state:', e);
            }
        }
    }

    clear() {
        this.currentState = null;
        this.sessionId = null;
        this.stateMetadata = {};
        this.transitions = [];
        this.lastUpdate = null;
        sessionStorage.removeItem('mfaStateTracker');
    }
}

// 전역 인스턴스 생성
window.mfaStateTracker = new MfaStateTracker();