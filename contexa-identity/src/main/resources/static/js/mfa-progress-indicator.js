// src/main/resources/static/js/mfa-progress-indicator.js
// MFA 진행 상태 시각화 모듈

class MfaProgressIndicator {
    constructor(containerId = 'mfaProgressContainer') {
        this.containerId = containerId;
        this.container = null;
        this.initialized = false;
    }

    /**
     * 진행 상태 표시기 초기화
     */
    init() {
        this.container = document.getElementById(this.containerId);
        if (!this.container) {
            console.warn(`Progress indicator container '${this.containerId}' not found`);
            return false;
        }

        // 진행 상태 HTML 구조 생성
        this.container.innerHTML = `
            <div class="mfa-progress-wrapper bg-white p-4 rounded-lg shadow-md mb-6">
                <div class="flex items-center justify-between mb-2">
                    <h3 class="text-sm font-semibold text-gray-700">인증 진행 상태</h3>
                    <span id="mfaProgressPercent" class="text-sm font-medium text-app-accent">0%</span>
                </div>
                <div class="w-full bg-gray-200 rounded-full h-2.5 mb-2">
                    <div id="mfaProgressBar" class="bg-app-accent h-2.5 rounded-full transition-all duration-500 ease-out" style="width: 0%"></div>
                </div>
                <p id="mfaStateDescription" class="text-xs text-gray-600 text-center">인증을 시작해주세요</p>
                <div id="mfaStepIndicators" class="flex justify-between mt-4">
                    <div class="mfa-step" data-step="1">
                        <div class="w-8 h-8 rounded-full bg-gray-300 flex items-center justify-center text-xs font-semibold text-white transition-colors duration-300">1</div>
                        <p class="text-xs mt-1 text-gray-600">로그인</p>
                    </div>
                    <div class="mfa-step" data-step="2">
                        <div class="w-8 h-8 rounded-full bg-gray-300 flex items-center justify-center text-xs font-semibold text-white transition-colors duration-300">2</div>
                        <p class="text-xs mt-1 text-gray-600">선택</p>
                    </div>
                    <div class="mfa-step" data-step="3">
                        <div class="w-8 h-8 rounded-full bg-gray-300 flex items-center justify-center text-xs font-semibold text-white transition-colors duration-300">3</div>
                        <p class="text-xs mt-1 text-gray-600">인증</p>
                    </div>
                    <div class="mfa-step" data-step="4">
                        <div class="w-8 h-8 rounded-full bg-gray-300 flex items-center justify-center text-xs font-semibold text-white transition-colors duration-300">4</div>
                        <p class="text-xs mt-1 text-gray-600">완료</p>
                    </div>
                </div>
            </div>
        `;

        this.initialized = true;
        return true;
    }

    /**
     * State Machine 상태를 기반으로 진행 상태 업데이트
     */
    update(currentState, stateMetadata = {}) {
        if (!this.initialized && !this.init()) {
            return;
        }

        const progressBar = document.getElementById('mfaProgressBar');
        const progressPercent = document.getElementById('mfaProgressPercent');
        const stateDescription = document.getElementById('mfaStateDescription');

        // 상태별 진행률 및 단계 매핑
        const stateConfig = {
            'INITIAL': {
                progress: 0,
                step: 0,
                description: '인증을 시작해주세요'
            },
            'PRIMARY_AUTH_SUCCESS': {
                progress: 25,
                step: 1,
                description: '1차 인증 완료'
            },
            'AWAITING_FACTOR_SELECTION': {
                progress: 40,
                step: 2,
                description: '2차 인증 수단을 선택해주세요'
            },
            'OTT_CHALLENGE': {
                progress: 60,
                step: 3,
                description: 'OTT 코드를 입력해주세요'
            },
            'PASSKEY_CHALLENGE': {
                progress: 60,
                step: 3,
                description: 'Passkey로 인증해주세요'
            },
            'OTT_VERIFIED': {
                progress: 80,
                step: 3,
                description: 'OTT 인증 완료'
            },
            'PASSKEY_VERIFIED': {
                progress: 80,
                step: 3,
                description: 'Passkey 인증 완료'
            },
            'COMPLETED': {
                progress: 100,
                step: 4,
                description: '모든 인증이 완료되었습니다!'
            },
            'FAILED': {
                progress: 0,
                step: -1,
                description: '인증에 실패했습니다'
            },
            'CANCELLED': {
                progress: 0,
                step: -1,
                description: '인증이 취소되었습니다'
            }
        };

        const config = stateConfig[currentState] || { progress: 0, step: 0, description: '알 수 없는 상태' };

        // 진행률 업데이트
        if (progressBar) {
            progressBar.style.width = `${config.progress}%`;
            if (config.step === -1) {
                progressBar.classList.remove('bg-app-accent');
                progressBar.classList.add('bg-red-500');
            } else {
                progressBar.classList.remove('bg-red-500');
                progressBar.classList.add('bg-app-accent');
            }
        }

        if (progressPercent) {
            progressPercent.textContent = `${config.progress}%`;
        }

        // 상태 설명 업데이트
        if (stateDescription) {
            let description = config.description;

            // 메타데이터 기반 추가 정보
            if (stateMetadata.attemptsRemaining !== undefined && stateMetadata.attemptsRemaining < 3) {
                description += ` (남은 시도: ${stateMetadata.attemptsRemaining}회)`;
            }
            if (stateMetadata.failureReason) {
                description += ` - ${this.getFailureReasonText(stateMetadata.failureReason)}`;
            }

            stateDescription.textContent = description;

            if (config.step === -1) {
                stateDescription.classList.remove('text-gray-600');
                stateDescription.classList.add('text-red-600');
            } else {
                stateDescription.classList.remove('text-red-600');
                stateDescription.classList.add('text-gray-600');
            }
        }

        // 단계 표시기 업데이트
        this.updateStepIndicators(config.step);
    }

    /**
     * 단계 표시기 업데이트
     */
    updateStepIndicators(currentStep) {
        const steps = document.querySelectorAll('.mfa-step');

        steps.forEach((stepEl, index) => {
            const stepNum = index + 1;
            const indicator = stepEl.querySelector('div');

            if (stepNum <= currentStep) {
                // 완료된 단계
                indicator.classList.remove('bg-gray-300');
                indicator.classList.add('bg-app-accent');
            } else if (stepNum === currentStep + 1) {
                // 현재 단계
                indicator.classList.remove('bg-gray-300', 'bg-app-accent');
                indicator.classList.add('bg-app-primary', 'ring-2', 'ring-app-primary', 'ring-opacity-50');
            } else {
                // 미완료 단계
                indicator.classList.remove('bg-app-accent', 'bg-app-primary', 'ring-2', 'ring-app-primary', 'ring-opacity-50');
                indicator.classList.add('bg-gray-300');
            }

            // 실패 상태일 때
            if (currentStep === -1) {
                indicator.classList.remove('bg-app-accent', 'bg-app-primary');
                indicator.classList.add('bg-red-300');
            }
        });
    }

    /**
     * 실패 이유를 사용자 친화적인 텍스트로 변환
     */
    getFailureReasonText(reason) {
        const reasonTexts = {
            'INVALID_CREDENTIALS': '잘못된 인증 정보',
            'MAX_ATTEMPTS_EXCEEDED': '최대 시도 횟수 초과',
            'SESSION_EXPIRED': '세션 만료',
            'INVALID_STATE_TRANSITION': '잘못된 인증 흐름',
            'FACTOR_NOT_AVAILABLE': '사용할 수 없는 인증 수단',
            'OTT_EXPIRED': 'OTT 코드 만료',
            'PASSKEY_VERIFICATION_FAILED': 'Passkey 인증 실패'
        };

        return reasonTexts[reason] || '인증 오류';
    }

    /**
     * 진행 상태 표시기 숨기기
     */
    hide() {
        if (this.container) {
            this.container.style.display = 'none';
        }
    }

    /**
     * 진행 상태 표시기 보이기
     */
    show() {
        if (this.container) {
            this.container.style.display = 'block';
        }
    }
}

// 전역 인스턴스 생성
window.mfaProgressIndicator = new MfaProgressIndicator();

// State Tracker와 연동
if (window.mfaStateTracker) {
    // State Tracker의 update 메서드를 오버라이드하여 자동으로 진행 상태 업데이트
    const originalUpdate = window.mfaStateTracker.updateFromServerResponse;
    window.mfaStateTracker.updateFromServerResponse = function(response) {
        originalUpdate.call(this, response);

        // 진행 상태 표시기 업데이트
        if (window.mfaProgressIndicator && this.currentState) {
            window.mfaProgressIndicator.update(this.currentState, this.stateMetadata);
        }
    };
}