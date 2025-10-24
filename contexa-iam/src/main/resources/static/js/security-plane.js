/**
 * Security Plane Simulator
 * 보안 평면 시뮬레이션을 위한 JavaScript 구현
 */
class SecurityPlaneSimulator {
    constructor() {
        this.wsConnection = null;
        this.sseConnection = null;
        this.approvalQueue = new Map();
        this.metrics = {
            totalEvents: 0,
            threatsDetected: 0,
            toolsExecuted: 0,
            approvalsGranted: 0,
            approvalsDenied: 0
        };
        this.eventLog = [];
        this.init();
    }

    init() {
        this.connectWebSocket();
        this.connectSSE();
        this.bindEventHandlers();
        this.startMetricsUpdate();
    }

    /**
     * WebSocket 연결 설정
     */
    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        try {
            this.wsConnection = new WebSocket(wsUrl);
            
            this.wsConnection.onopen = () => {
                this.updateConnectionStatus('connected');
                this.logAction('WebSocket 연결 성공', 'success');
            };

            this.wsConnection.onmessage = (event) => {
                this.handleWebSocketMessage(JSON.parse(event.data));
            };

            this.wsConnection.onerror = (error) => {
                this.updateConnectionStatus('error');
                this.logAction('WebSocket 연결 오류', 'error');
                console.error('WebSocket error:', error);
            };

            this.wsConnection.onclose = () => {
                this.updateConnectionStatus('disconnected');
                this.logAction('WebSocket 연결 종료', 'warning');
                // 5초 후 재연결 시도
                setTimeout(() => this.connectWebSocket(), 5000);
            };
        } catch (error) {
            console.error('WebSocket 연결 실패:', error);
            this.updateConnectionStatus('error');
        }
    }

    /**
     * SSE 연결 설정
     */
    connectSSE() {
        try {
            this.sseConnection = new EventSource('/api/security/sse/stream');
            
            this.sseConnection.onopen = () => {
                this.logAction('SSE 스트림 연결 성공', 'success');
            };

            this.sseConnection.onmessage = (event) => {
                this.handleSSEMessage(JSON.parse(event.data));
            };

            this.sseConnection.onerror = (error) => {
                console.error('SSE error:', error);
                this.logAction('SSE 스트림 오류', 'error');
            };
        } catch (error) {
            console.error('SSE 연결 실패:', error);
        }
    }

    /**
     * WebSocket 메시지 처리
     */
    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'THREAT_DETECTED':
                this.onThreatDetected(message);
                break;
            case 'TOOL_EXECUTION':
                this.onToolExecution(message);
                break;
            case 'APPROVAL_REQUEST':
                this.onApprovalRequest(message);
                break;
            case 'SECURITY_EVENT':
                this.onSecurityEvent(message);
                break;
            case 'LEARNING_UPDATE':
                this.onLearningUpdate(message);
                break;
            default:
                console.log('Unknown message type:', message.type);
        }
    }

    /**
     * SSE 메시지 처리
     */
    handleSSEMessage(message) {
        if (message.event === 'approval') {
            this.addToApprovalQueue(message.data);
        } else if (message.event === 'metrics') {
            this.updateMetrics(message.data);
        }
    }

    /**
     * 보안 이벤트 생성 및 전송
     */
    async generateEvent() {
        const eventData = {
            eventType: document.getElementById('eventType').value,
            threatLevel: document.getElementById('threatLevel').value,
            sourceIp: document.getElementById('sourceIp').value,
            targetAsset: document.getElementById('targetAsset').value,
            mitreMapping: document.getElementById('mitreMapping').value,
            timestamp: new Date().toISOString(),
            details: {
                description: `Simulated ${document.getElementById('eventType').value} event`,
                severity: this.calculateSeverity(document.getElementById('threatLevel').value),
                indicators: this.generateIndicators()
            }
        };

        try {
            // 1. 이벤트 수집 (Kafka/Redis로 전송)
            this.updateFlowStep(1, 'active');
            const collectResponse = await fetch('/api/security-plane/events/collect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(eventData)
            });

            if (collectResponse.ok) {
                this.metrics.totalEvents++;
                this.logAction(`이벤트 생성: ${eventData.eventType}`, 'info');
                
                // 2. 위협 평가
                setTimeout(() => this.performThreatAssessment(eventData), 1000);
            }
        } catch (error) {
            console.error('Event generation failed:', error);
            this.logAction('이벤트 생성 실패', 'error');
        }
    }

    /**
     * 위협 평가 수행
     */
    async performThreatAssessment(eventData) {
        this.updateFlowStep(2, 'active');
        
        try {
            const assessmentResponse = await fetch('/api/security-plane/threat/assess', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(eventData)
            });

            if (assessmentResponse.ok) {
                const assessment = await assessmentResponse.json();
                this.logAction(`위협 평가 완료: 위험도 ${assessment.riskScore}`, 'warning');
                
                if (assessment.isThreat) {
                    this.metrics.threatsDetected++;
                    // 3. 트리거 조건 확인
                    setTimeout(() => this.checkTriggerConditions(eventData, assessment), 1000);
                } else {
                    this.updateFlowStep(2, 'completed');
                    this.logAction('위협 없음 - 프로세스 종료', 'success');
                }
            }
        } catch (error) {
            console.error('Threat assessment failed:', error);
            this.logAction('위협 평가 실패', 'error');
        }
    }

    /**
     * 트리거 조건 확인
     */
    async checkTriggerConditions(eventData, assessment) {
        this.updateFlowStep(3, 'active');
        
        try {
            const triggerResponse = await fetch('/api/security-plane/trigger/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ event: eventData, assessment })
            });

            if (triggerResponse.ok) {
                const trigger = await triggerResponse.json();
                this.logAction(`트리거 매칭: ${trigger.mappings.join(', ')}`, 'info');
                
                if (trigger.shouldExecute) {
                    // 4. SoarContext 설정
                    setTimeout(() => this.configureSoarContext(eventData, assessment, trigger), 1000);
                } else {
                    this.updateFlowStep(3, 'completed');
                    this.logAction('트리거 조건 미충족', 'info');
                }
            }
        } catch (error) {
            console.error('Trigger check failed:', error);
            this.logAction('트리거 확인 실패', 'error');
        }
    }

    /**
     * SoarContext 설정
     */
    async configureSoarContext(eventData, assessment, trigger) {
        this.updateFlowStep(4, 'active');
        
        const soarContext = {
            event: eventData,
            assessment: assessment,
            trigger: trigger,
            timestamp: new Date().toISOString(),
            contextId: this.generateContextId()
        };

        try {
            const contextResponse = await fetch('/api/security-plane/soar/configure', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(soarContext)
            });

            if (contextResponse.ok) {
                const context = await contextResponse.json();
                this.logAction(`SoarContext 생성: ${context.contextId}`, 'success');
                
                // 5. SoarLab 실행
                setTimeout(() => this.executeSoarLab(context), 1000);
            }
        } catch (error) {
            console.error('SoarContext configuration failed:', error);
            this.logAction('SoarContext 설정 실패', 'error');
        }
    }

    /**
     * SoarLab 실행 (AI가 MCP 도구 선택)
     */
    async executeSoarLab(context) {
        this.updateFlowStep(5, 'active');
        
        try {
            const soarResponse = await fetch('/api/security-plane/soar/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(context)
            });

            if (soarResponse.ok) {
                const soarResult = await soarResponse.json();
                this.logAction(`SoarLab 실행: ${soarResult.selectedTools.length}개 도구 선택`, 'info');
                
                // 선택된 도구 표시
                soarResult.selectedTools.forEach(tool => {
                    this.logAction(`  - ${tool.name} (위험도: ${tool.riskLevel})`, 'info');
                });

                // 6. 위험 기반 승인
                setTimeout(() => this.processApproval(context, soarResult), 1000);
            }
        } catch (error) {
            console.error('SoarLab execution failed:', error);
            this.logAction('SoarLab 실행 실패', 'error');
        }
    }

    /**
     * 위험 기반 승인 처리
     */
    async processApproval(context, soarResult) {
        this.updateFlowStep(6, 'active');
        
        const riskLevel = soarResult.overallRisk;
        let approvalData = {
            contextId: context.contextId,
            tools: soarResult.selectedTools,
            riskLevel: riskLevel,
            timestamp: new Date().toISOString()
        };

        switch (riskLevel) {
            case 'LOW':
                // 자동 승인 및 실행
                this.logAction('낮은 위험 - 자동 승인', 'success');
                this.autoApprove(approvalData);
                break;
            
            case 'MEDIUM':
                // 지연 후 자동 실행
                this.logAction('중간 위험 - 5초 후 자동 실행', 'warning');
                setTimeout(() => this.autoApprove(approvalData), 5000);
                break;
            
            case 'HIGH':
                // 사용자 승인 대기
                this.logAction('높은 위험 - 사용자 승인 대기', 'warning');
                this.addToApprovalQueue(approvalData);
                break;
            
            case 'CRITICAL':
                // 격리 후 승인 대기
                this.logAction('치명적 위험 - 격리 후 승인 대기', 'error');
                await this.isolateSystem(context);
                this.addToApprovalQueue(approvalData);
                break;
        }
    }

    /**
     * 자동 승인 처리
     */
    async autoApprove(approvalData) {
        try {
            const approveResponse = await fetch('/api/security-plane/approval/auto', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(approvalData)
            });

            if (approveResponse.ok) {
                this.metrics.approvalsGranted++;
                this.logAction('도구 자동 승인 및 실행', 'success');
                this.executeTools(approvalData);
            }
        } catch (error) {
            console.error('Auto approval failed:', error);
            this.logAction('자동 승인 실패', 'error');
        }
    }

    /**
     * 도구 실행 (DB 저장된 도구 실행)
     */
    async executeTools(approvalData) {
        this.updateFlowStep(7, 'active');
        
        try {
            // DB에 저장된 도구 실행 컨텍스트를 사용하여 실행
            const executeResponse = await fetch('/api/security-plane/tools/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contextId: approvalData.contextId,
                    tools: approvalData.tools,
                    executeFromDb: true  // DB에 저장된 도구 실행 플래그
                })
            });

            if (executeResponse.ok) {
                const result = await executeResponse.json();
                this.metrics.toolsExecuted += result.executedTools.length;
                this.logAction(`${result.executedTools.length}개 도구 실행 완료`, 'success');
                
                // 학습 및 피드백
                this.recordLearning(approvalData, result);
                
                // 플로우 완료
                this.updateFlowStep(7, 'completed');
            }
        } catch (error) {
            console.error('Tool execution failed:', error);
            this.logAction('도구 실행 실패', 'error');
        }
    }

    /**
     * 승인 큐에 추가
     */
    addToApprovalQueue(approvalData) {
        const queueId = `approval-${Date.now()}`;
        this.approvalQueue.set(queueId, approvalData);
        
        const queueHtml = `
            <div class="approval-item" data-queue-id="${queueId}">
                <div class="approval-header">
                    <span class="risk-badge risk-${approvalData.riskLevel.toLowerCase()}">${approvalData.riskLevel}</span>
                    <span class="approval-time">${new Date(approvalData.timestamp).toLocaleTimeString()}</span>
                </div>
                <div class="approval-tools">
                    ${approvalData.tools.map(t => `<div>• ${t.name}</div>`).join('')}
                </div>
                <div class="approval-actions">
                    <button class="btn btn-success btn-sm" onclick="simulator.approveRequest('${queueId}')">승인</button>
                    <button class="btn btn-danger btn-sm" onclick="simulator.denyRequest('${queueId}')">거부</button>
                    <button class="btn btn-info btn-sm" onclick="simulator.viewDetails('${queueId}')">상세</button>
                </div>
            </div>
        `;
        
        document.getElementById('approvalQueue').insertAdjacentHTML('afterbegin', queueHtml);
    }

    /**
     * 사용자 승인 처리
     */
    async approveRequest(queueId) {
        const approvalData = this.approvalQueue.get(queueId);
        if (!approvalData) return;

        try {
            const approveResponse = await fetch('/api/security-plane/approval/approve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contextId: approvalData.contextId,
                    approved: true,
                    timestamp: new Date().toISOString()
                })
            });

            if (approveResponse.ok) {
                this.metrics.approvalsGranted++;
                this.logAction(`사용자 승인: ${approvalData.contextId}`, 'success');
                
                // DB에 저장된 도구 실행
                await this.executeTools(approvalData);
                
                // 큐에서 제거
                this.removeFromQueue(queueId);
            }
        } catch (error) {
            console.error('Approval failed:', error);
            this.logAction('승인 처리 실패', 'error');
        }
    }

    /**
     * 사용자 거부 처리
     */
    async denyRequest(queueId) {
        const approvalData = this.approvalQueue.get(queueId);
        if (!approvalData) return;

        try {
            const denyResponse = await fetch('/api/security-plane/approval/deny', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contextId: approvalData.contextId,
                    approved: false,
                    reason: 'User denied',
                    timestamp: new Date().toISOString()
                })
            });

            if (denyResponse.ok) {
                this.metrics.approvalsDenied++;
                this.logAction(`사용자 거부: ${approvalData.contextId}`, 'warning');
                this.removeFromQueue(queueId);
            }
        } catch (error) {
            console.error('Denial failed:', error);
            this.logAction('거부 처리 실패', 'error');
        }
    }

    /**
     * 상세 정보 보기
     */
    async viewDetails(queueId) {
        const approvalData = this.approvalQueue.get(queueId);
        if (!approvalData) return;

        // 상세 정보 모달 표시
        const detailsHtml = `
            <div class="modal fade" id="detailsModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">승인 요청 상세</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <h6>Context ID: ${approvalData.contextId}</h6>
                            <p>위험 수준: <span class="risk-badge risk-${approvalData.riskLevel.toLowerCase()}">${approvalData.riskLevel}</span></p>
                            <h6>선택된 도구:</h6>
                            <ul>
                                ${approvalData.tools.map(t => `
                                    <li>
                                        <strong>${t.name}</strong> (위험도: ${t.riskLevel})
                                        <br>설명: ${t.description || 'N/A'}
                                        <br>파라미터: <code>${JSON.stringify(t.parameters || {})}</code>
                                    </li>
                                `).join('')}
                            </ul>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">닫기</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', detailsHtml);
        const modal = new bootstrap.Modal(document.getElementById('detailsModal'));
        modal.show();
        
        // 모달 닫힐 때 DOM에서 제거
        document.getElementById('detailsModal').addEventListener('hidden.bs.modal', function() {
            this.remove();
        });
    }

    /**
     * 큐에서 제거
     */
    removeFromQueue(queueId) {
        this.approvalQueue.delete(queueId);
        const element = document.querySelector(`[data-queue-id="${queueId}"]`);
        if (element) {
            element.remove();
        }
    }

    /**
     * 시스템 격리
     */
    async isolateSystem(context) {
        try {
            const isolateResponse = await fetch('/api/security-plane/isolate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(context)
            });

            if (isolateResponse.ok) {
                this.logAction('시스템 격리 완료', 'error');
            }
        } catch (error) {
            console.error('System isolation failed:', error);
        }
    }

    /**
     * 학습 기록
     */
    async recordLearning(approvalData, executionResult) {
        try {
            const learningResponse = await fetch('/api/security-plane/learning/record', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    context: approvalData,
                    result: executionResult,
                    timestamp: new Date().toISOString()
                })
            });

            if (learningResponse.ok) {
                this.logAction('학습 데이터 기록 완료', 'info');
            }
        } catch (error) {
            console.error('Learning record failed:', error);
        }
    }

    /**
     * 플로우 단계 업데이트
     */
    updateFlowStep(step, status) {
        // 모든 단계 비활성화
        document.querySelectorAll('.flow-step').forEach(el => {
            el.classList.remove('active', 'completed');
        });

        // 현재 단계까지 활성화
        for (let i = 1; i <= step; i++) {
            const stepEl = document.getElementById(`step-${i}`);
            if (stepEl) {
                if (i < step || status === 'completed') {
                    stepEl.classList.add('completed');
                }
                if (i === step && status === 'active') {
                    stepEl.classList.add('active');
                }
            }
        }
    }

    /**
     * 연결 상태 업데이트
     */
    updateConnectionStatus(status) {
        const statusEl = document.getElementById('connectionStatus');
        statusEl.className = `connection-status ${status}`;
        statusEl.textContent = status === 'connected' ? '연결됨' : 
                               status === 'error' ? '오류' : '연결 안됨';
    }

    /**
     * 액션 로그
     */
    logAction(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = { timestamp, message, type };
        this.eventLog.push(logEntry);

        const logHtml = `
            <div class="log-entry log-${type}">
                <span class="log-time">${timestamp}</span>
                <span class="log-message">${message}</span>
            </div>
        `;
        
        const logContainer = document.getElementById('actionLog');
        logContainer.insertAdjacentHTML('afterbegin', logHtml);
        
        // 최대 100개 로그만 유지
        while (logContainer.children.length > 100) {
            logContainer.removeChild(logContainer.lastChild);
        }
    }

    /**
     * 메트릭스 업데이트
     */
    updateMetrics(newMetrics) {
        if (newMetrics) {
            Object.assign(this.metrics, newMetrics);
        }
        
        document.getElementById('totalEvents').textContent = this.metrics.totalEvents;
        document.getElementById('threatsDetected').textContent = this.metrics.threatsDetected;
        document.getElementById('toolsExecuted').textContent = this.metrics.toolsExecuted;
        document.getElementById('approvalsGranted').textContent = this.metrics.approvalsGranted;
    }

    /**
     * 메트릭스 주기적 업데이트
     */
    startMetricsUpdate() {
        setInterval(() => {
            this.updateMetrics();
        }, 5000);
    }

    /**
     * 3계층별 공격 시뮬레이션 생성
     */
    async generateLayerAttack(layer) {
        // 계층별 공격 시나리오 정의
        const layerAttacks = {
            layer1: {
                eventType: 'INTRUSION_ATTEMPT',
                threatLevel: 'HIGH',
                sourceIp: '203.0.113.45',
                targetAsset: 'web-server-01',
                mitreMapping: 'T1110.001',
                description: 'SSH 무차별 대입 공격 (Layer 1 빠른 필터링)',
                tags: ['brute-force', 'ssh', 'external', 'layer1'],
                expectedResponse: '~50ms (TinyLlama)',
                processingLayer: 'Layer 1 - 빠른 필터링'
            },
            layer2: {
                eventType: 'PRIVILEGE_ESCALATION',
                threatLevel: 'HIGH',
                sourceIp: '192.168.100.50',
                targetAsset: 'domain-controller',
                mitreMapping: 'T1078.004',
                description: '권한 상승 시도 (Layer 2 컨텍스트 분석)',
                tags: ['privilege-escalation', 'admin', 'ad', 'layer2'],
                expectedResponse: '~300ms (Llama3.1:8b)',
                processingLayer: 'Layer 2 - 컨텍스트 분석'
            },
            layer3: {
                eventType: 'DATA_EXFILTRATION',
                threatLevel: 'CRITICAL',
                sourceIp: '192.168.100.50',
                targetAsset: 'database-server',
                mitreMapping: 'T1041',
                description: '데이터 유출 시도 (Layer 3 전문가 분석)',
                tags: ['data-exfiltration', 'database', 'critical', 'layer3'],
                expectedResponse: '~5s (Claude Opus/GPT-4)',
                processingLayer: 'Layer 3 - 전문가 분석'
            }
        };

        const attackConfig = layerAttacks[layer];
        if (!attackConfig) {
            this.logAction(`잘못된 계층: ${layer}`, 'error');
            return;
        }

        // UI 상태 업데이트
        this.updateLayerStatus(layer, 'processing');
        this.logAction(`${attackConfig.processingLayer} 공격 시뮬레이션 시작`, 'info');

        const startTime = performance.now();

        const eventData = {
            eventType: attackConfig.eventType,
            threatLevel: attackConfig.threatLevel,
            sourceIp: attackConfig.sourceIp,
            targetAsset: attackConfig.targetAsset,
            mitreMapping: attackConfig.mitreMapping,
            tierLayer: layer,  // 계층 정보 추가
            timestamp: new Date().toISOString(),
            details: {
                description: attackConfig.description,
                severity: this.calculateSeverity(attackConfig.threatLevel),
                indicators: this.generateIndicators(),
                processingLayer: attackConfig.processingLayer,
                tags: attackConfig.tags
            }
        };

        try {
            // 계층별 시뮬레이션 API 호출
            const response = await fetch(`/api/security-plane/simulate/${layer}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(eventData)
            });

            const endTime = performance.now();
            const actualResponseTime = Math.round(endTime - startTime);

            if (response.ok) {
                const result = await response.json();
                this.metrics.totalEvents++;
                
                // 계층별 카운터 증가
                this.updateLayerCount(layer);
                this.updateLayerTime(layer, `${actualResponseTime}ms`);
                this.updateLayerStatus(layer, 'completed');
                
                this.logAction(
                    `${attackConfig.processingLayer} 처리 완료 (${actualResponseTime}ms) - ${result.decision || '차단됨'}`, 
                    'success'
                );
                
                // 7단계 자율보안 프로세스 시작
                this.startAutonomousSecurityProcess(eventData, result);
                
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        } catch (error) {
            this.updateLayerStatus(layer, 'error');
            this.logAction(`${attackConfig.processingLayer} 시뮬레이션 실패: ${error.message}`, 'error');
            console.error(`Layer ${layer} attack simulation failed:`, error);
        }
    }

    /**
     * 계층별 상태 업데이트
     */
    updateLayerStatus(layer, status) {
        const statusElement = document.getElementById(`${layer}Status`);
        if (statusElement) {
            statusElement.className = `status-${status}`;
            statusElement.textContent = {
                'processing': '처리 중...',
                'completed': '활성',
                'error': '오류'
            }[status] || '활성';
        }
    }

    /**
     * 계층별 처리 건수 증가
     */
    updateLayerCount(layer) {
        const countElement = document.getElementById(`${layer}Count`);
        if (countElement) {
            const currentCount = parseInt(countElement.textContent) || 0;
            countElement.textContent = currentCount + 1;
        }
    }

    /**
     * 계층별 처리 시간 업데이트
     */
    updateLayerTime(layer, time) {
        const timeElement = document.getElementById(`${layer}Time`);
        if (timeElement) {
            timeElement.textContent = time;
        }
    }

    /**
     * 7단계 자율보안 프로세스 시작
     */
    async startAutonomousSecurityProcess(eventData, analysisResult) {
        this.logAction('7단계 자율보안 프로세스 시작', 'info');
        
        // 1단계: 이벤트 수집 (이미 완료)
        this.updateFlowStep(1, 'completed');
        
        // 2단계: 위협 평가
        setTimeout(() => this.performThreatAssessment(eventData, analysisResult), 500);
    }

    /**
     * 이벤트 핸들러 바인딩
     */
    bindEventHandlers() {
        document.getElementById('generateEvent').addEventListener('click', () => {
            this.generateEvent();
        });

        document.getElementById('clearLogs').addEventListener('click', () => {
            document.getElementById('actionLog').innerHTML = '';
            this.eventLog = [];
            this.logAction('로그 초기화', 'info');
        });

        document.getElementById('resetMetrics').addEventListener('click', () => {
            this.metrics = {
                totalEvents: 0,
                threatsDetected: 0,
                toolsExecuted: 0,
                approvalsGranted: 0,
                approvalsDenied: 0
            };
            this.updateMetrics();
            this.logAction('메트릭스 초기화', 'info');
        });

        // 3계층 AI 보안 시뮬레이션 이벤트 핸들러
        document.getElementById('layer1Attack').addEventListener('click', () => {
            this.generateLayerAttack('layer1');
        });

        document.getElementById('layer2Attack').addEventListener('click', () => {
            this.generateLayerAttack('layer2');
        });

        document.getElementById('layer3Attack').addEventListener('click', () => {
            this.generateLayerAttack('layer3');
        });
    }

    // 이벤트 핸들러 메서드들
    onThreatDetected(message) {
        this.metrics.threatsDetected++;
        this.logAction(`위협 탐지: ${message.threat.type}`, 'warning');
        this.updateMetrics();
    }

    onToolExecution(message) {
        this.metrics.toolsExecuted++;
        this.logAction(`도구 실행: ${message.tool.name}`, 'info');
        this.updateMetrics();
    }

    onApprovalRequest(message) {
        this.addToApprovalQueue(message.approval);
        this.logAction(`승인 요청: ${message.approval.contextId}`, 'warning');
    }

    onSecurityEvent(message) {
        this.metrics.totalEvents++;
        this.logAction(`보안 이벤트: ${message.event.type}`, 'info');
        this.updateMetrics();
    }

    onLearningUpdate(message) {
        this.logAction(`학습 업데이트: ${message.learning.improvement}%`, 'success');
    }

    // 유틸리티 메서드들
    calculateSeverity(threatLevel) {
        const severityMap = {
            'LOW': 1,
            'MEDIUM': 5,
            'HIGH': 7,
            'CRITICAL': 10
        };
        return severityMap[threatLevel] || 1;
    }

    generateIndicators() {
        return [
            { type: 'IP', value: document.getElementById('sourceIp').value },
            { type: 'ASSET', value: document.getElementById('targetAsset').value },
            { type: 'MITRE', value: document.getElementById('mitreMapping').value }
        ];
    }

    generateContextId() {
        return `ctx-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }
}

// 페이지 로드 시 시뮬레이터 초기화
let simulator;
document.addEventListener('DOMContentLoaded', () => {
    simulator = new SecurityPlaneSimulator();
    console.log('Security Plane Simulator initialized');
});