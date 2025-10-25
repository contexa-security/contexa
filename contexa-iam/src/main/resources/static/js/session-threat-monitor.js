/**
 * Session Threat Monitor
 *
 * HTTP Response Header를 통해 세션 위협 정보를 감지하고 사용자에게 알림을 표시합니다.
 * 모든 AJAX 요청과 fetch API 호출을 모니터링하여 세션 위협을 실시간으로 감지합니다.
 *
 * @author contexa
 * @since 1.0
 */

(function() {
    'use strict';

    // 세션 위협 모니터 객체
    const SessionThreatMonitor = {
        // 설정
        config: {
            checkInterval: 5000, // 5초마다 헤더 체크
            modalShown: false,   // 모달이 표시되었는지 여부
            lastThreatLevel: null, // 마지막 위협 레벨
            gracePeriodWarningShown: false, // Grace Period 경고 표시 여부
            monitoringEnabled: true  // 모니터링 활성화 여부
        },

        // 초기화
        init: function() {
            console.log('[SessionThreatMonitor] Initializing...');

            // XMLHttpRequest 인터셉트
            this.interceptXHR();

            // Fetch API 인터셉트
            this.interceptFetch();

            // 페이지 로드 시 체크
            this.checkCurrentPage();

            console.log('[SessionThreatMonitor] Initialized successfully');
        },

        // XMLHttpRequest 인터셉트
        interceptXHR: function() {
            const self = this;
            const originalOpen = XMLHttpRequest.prototype.open;
            const originalSend = XMLHttpRequest.prototype.send;

            XMLHttpRequest.prototype.open = function() {
                this._requestURL = arguments[1];
                originalOpen.apply(this, arguments);
            };

            XMLHttpRequest.prototype.send = function() {
                this.addEventListener('readystatechange', function() {
                    if (this.readyState === 4) {
                        self.checkResponseHeaders(this);
                    }
                });
                originalSend.apply(this, arguments);
            };
        },

        // Fetch API 인터셉트
        interceptFetch: function() {
            const self = this;
            const originalFetch = window.fetch;

            window.fetch = function() {
                return originalFetch.apply(this, arguments)
                    .then(function(response) {
                        self.checkFetchHeaders(response);
                        return response;
                    });
            };
        },

        // XMLHttpRequest 응답 헤더 체크
        checkResponseHeaders: function(xhr) {
            if (!this.config.monitoringEnabled) return;

            const threatLevel = xhr.getResponseHeader('X-Session-Threat');
            if (!threatLevel) return;

            const threatInfo = {
                level: threatLevel,
                score: xhr.getResponseHeader('X-Threat-Score'),
                action: xhr.getResponseHeader('X-Session-Action'),
                ttl: xhr.getResponseHeader('X-Session-TTL'),
                gracePeriod: xhr.getResponseHeader('X-Grace-Period'),
                recoveryUrl: xhr.getResponseHeader('X-Recovery-URL')
            };

            this.handleThreatDetected(threatInfo);
        },

        // Fetch API 응답 헤더 체크
        checkFetchHeaders: function(response) {
            if (!this.config.monitoringEnabled) return;

            const threatLevel = response.headers.get('X-Session-Threat');
            if (!threatLevel) return;

            const threatInfo = {
                level: threatLevel,
                score: response.headers.get('X-Threat-Score'),
                action: response.headers.get('X-Session-Action'),
                ttl: response.headers.get('X-Session-TTL'),
                gracePeriod: response.headers.get('X-Grace-Period'),
                recoveryUrl: response.headers.get('X-Recovery-URL')
            };

            this.handleThreatDetected(threatInfo);
        },

        // 위협 감지 처리
        handleThreatDetected: function(threatInfo) {
            console.log('[SessionThreatMonitor] Threat detected:', threatInfo);

            // 위협 레벨별 처리
            switch(threatInfo.level) {
                case 'CRITICAL':
                    this.handleCriticalThreat(threatInfo);
                    break;
                case 'HIGH':
                    this.handleHighThreat(threatInfo);
                    break;
                case 'MEDIUM':
                    this.handleMediumThreat(threatInfo);
                    break;
                default:
                    console.warn('[SessionThreatMonitor] Unknown threat level:', threatInfo.level);
            }

            // 위협 레벨 저장
            this.config.lastThreatLevel = threatInfo.level;
        },

        // CRITICAL 위협 처리 (지연된 무효화)
        handleCriticalThreat: function(threatInfo) {
            if (this.config.modalShown) return;

            const ttl = parseInt(threatInfo.ttl) || 30;

            // 긴급 경고 모달 표시
            this.showModal({
                type: 'danger',
                title: '보안 경고: 세션이 곧 종료됩니다',
                message: `
                    <div class="alert alert-danger">
                        <strong>심각한 보안 위협이 감지되었습니다.</strong><br>
                        위협 점수: ${threatInfo.score || 'N/A'}<br>
                        <br>
                        보안을 위해 ${ttl}초 후 세션이 자동으로 종료됩니다.<br>
                        중요한 작업을 저장하고 다시 로그인해 주세요.
                    </div>
                    <div class="countdown-timer" id="session-countdown">
                        남은 시간: <span id="countdown-seconds">${ttl}</span>초
                    </div>
                `,
                buttons: [
                    {
                        text: '지금 로그아웃',
                        class: 'btn-danger',
                        action: function() {
                            window.location.href = '/logout';
                        }
                    },
                    {
                        text: '작업 저장',
                        class: 'btn-warning',
                        action: function() {
                            SessionThreatMonitor.saveCurrentWork();
                        }
                    }
                ],
                countdown: ttl,
                onTimeout: function() {
                    window.location.href = '/logout';
                }
            });
        },

        // HIGH 위협 처리 (Grace Period)
        handleHighThreat: function(threatInfo) {
            if (this.config.gracePeriodWarningShown) return;

            const gracePeriod = parseInt(threatInfo.gracePeriod) || 300;
            const minutes = Math.floor(gracePeriod / 60);

            // Grace Period 경고 표시
            this.showModal({
                type: 'warning',
                title: '재인증이 필요합니다',
                message: `
                    <div class="alert alert-warning">
                        <strong>비정상적인 활동이 감지되었습니다.</strong><br>
                        위협 점수: ${threatInfo.score || 'N/A'}<br>
                        <br>
                        계속 사용하시려면 ${minutes}분 이내에 재인증을 완료해 주세요.<br>
                        재인증하지 않으면 보안을 위해 세션이 종료됩니다.
                    </div>
                `,
                buttons: [
                    {
                        text: '지금 재인증',
                        class: 'btn-primary',
                        action: function() {
                            window.location.href = threatInfo.recoveryUrl || '/auth/step-up';
                        }
                    },
                    {
                        text: '나중에',
                        class: 'btn-secondary',
                        action: function() {
                            SessionThreatMonitor.config.gracePeriodWarningShown = true;
                            SessionThreatMonitor.closeModal();
                            SessionThreatMonitor.showGracePeriodReminder(gracePeriod);
                        }
                    }
                ]
            });
        },

        // MEDIUM 위협 처리 (모니터링)
        handleMediumThreat: function(threatInfo) {
            // 토스트 알림으로 간단히 표시
            this.showToast({
                type: 'info',
                message: '보안 모니터링이 강화되었습니다. 정상적인 활동을 계속하세요.',
                duration: 5000
            });
        },

        // Grace Period 리마인더 표시
        showGracePeriodReminder: function(seconds) {
            const reminderDiv = document.createElement('div');
            reminderDiv.id = 'grace-period-reminder';
            reminderDiv.className = 'grace-period-reminder';
            reminderDiv.innerHTML = `
                <div class="reminder-content">
                    <i class="fas fa-exclamation-triangle"></i>
                    재인증 필요: <span id="grace-countdown">${this.formatTime(seconds)}</span>
                    <button onclick="window.location.href='/auth/step-up'" class="btn btn-sm btn-primary">재인증</button>
                </div>
            `;
            document.body.appendChild(reminderDiv);

            // 카운트다운 업데이트
            const interval = setInterval(() => {
                seconds--;
                const countdownElement = document.getElementById('grace-countdown');
                if (countdownElement) {
                    countdownElement.textContent = this.formatTime(seconds);
                }
                if (seconds <= 0) {
                    clearInterval(interval);
                    window.location.href = '/logout';
                }
            }, 1000);
        },

        // 모달 표시
        showModal: function(options) {
            // 기존 모달 제거
            const existingModal = document.getElementById('threat-modal');
            if (existingModal) {
                existingModal.remove();
            }

            // 모달 HTML 생성
            const modalHtml = `
                <div class="modal fade show" id="threat-modal" tabindex="-1" style="display: block; background: rgba(0,0,0,0.5);">
                    <div class="modal-dialog modal-dialog-centered">
                        <div class="modal-content">
                            <div class="modal-header bg-${options.type}">
                                <h5 class="modal-title text-white">${options.title}</h5>
                            </div>
                            <div class="modal-body">
                                ${options.message}
                            </div>
                            <div class="modal-footer">
                                ${this.generateButtons(options.buttons)}
                            </div>
                        </div>
                    </div>
                </div>
            `;

            // 모달 추가
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            this.config.modalShown = true;

            // 버튼 이벤트 바인딩
            if (options.buttons) {
                options.buttons.forEach((btn, index) => {
                    const button = document.getElementById(`modal-btn-${index}`);
                    if (button && btn.action) {
                        button.addEventListener('click', btn.action);
                    }
                });
            }

            // 카운트다운 처리
            if (options.countdown) {
                this.startCountdown(options.countdown, options.onTimeout);
            }
        },

        // 버튼 HTML 생성
        generateButtons: function(buttons) {
            if (!buttons) return '';

            return buttons.map((btn, index) => `
                <button id="modal-btn-${index}" class="btn ${btn.class}">${btn.text}</button>
            `).join('');
        },

        // 카운트다운 시작
        startCountdown: function(seconds, onTimeout) {
            const interval = setInterval(() => {
                seconds--;
                const countdownElement = document.getElementById('countdown-seconds');
                if (countdownElement) {
                    countdownElement.textContent = seconds;
                }
                if (seconds <= 0) {
                    clearInterval(interval);
                    if (onTimeout) onTimeout();
                }
            }, 1000);
        },

        // 토스트 알림 표시
        showToast: function(options) {
            // 기존 toast.js 활용 (있는 경우)
            if (window.showToast) {
                window.showToast(options.message, options.type);
                return;
            }

            // 간단한 토스트 구현
            const toastDiv = document.createElement('div');
            toastDiv.className = `toast-notification toast-${options.type}`;
            toastDiv.textContent = options.message;
            toastDiv.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 15px 20px;
                background: #333;
                color: white;
                border-radius: 5px;
                z-index: 10000;
                animation: slideIn 0.3s ease;
            `;

            document.body.appendChild(toastDiv);

            setTimeout(() => {
                toastDiv.remove();
            }, options.duration || 3000);
        },

        // 모달 닫기
        closeModal: function() {
            const modal = document.getElementById('threat-modal');
            if (modal) {
                modal.remove();
                this.config.modalShown = false;
            }
        },

        // 현재 작업 저장
        saveCurrentWork: function() {
            // 자동 저장 로직 (필요시 구현)
            console.log('[SessionThreatMonitor] Saving current work...');

            // 폼 데이터 저장
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                const formData = new FormData(form);
                const data = {};
                formData.forEach((value, key) => {
                    data[key] = value;
                });
                localStorage.setItem(`saved-form-${form.id || 'default'}`, JSON.stringify(data));
            });

            this.showToast({
                type: 'success',
                message: '작업이 저장되었습니다.',
                duration: 3000
            });
        },

        // 현재 페이지 체크 (페이지 로드 시)
        checkCurrentPage: function() {
            // 메타 태그에서 세션 위협 정보 확인
            const metaThreat = document.querySelector('meta[name="session-threat"]');
            if (metaThreat) {
                const threatInfo = {
                    level: metaThreat.getAttribute('data-level'),
                    score: metaThreat.getAttribute('data-score'),
                    action: metaThreat.getAttribute('data-action')
                };
                if (threatInfo.level) {
                    this.handleThreatDetected(threatInfo);
                }
            }
        },

        // 시간 포맷팅
        formatTime: function(seconds) {
            const minutes = Math.floor(seconds / 60);
            const secs = seconds % 60;
            return `${minutes}:${secs.toString().padStart(2, '0')}`;
        }
    };

    // DOM 준비 후 초기화
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            SessionThreatMonitor.init();
        });
    } else {
        SessionThreatMonitor.init();
    }

    // 전역 객체로 노출 (디버깅용)
    window.SessionThreatMonitor = SessionThreatMonitor;
})();