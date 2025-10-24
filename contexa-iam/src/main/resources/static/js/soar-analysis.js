/**
 * SOAR Analysis Client - AI + MCP + SOAR Integration
 *
 * Enhanced version with WebSocket support for real-time updates,
 * AI pipeline visualization, and MCP server status monitoring.
 */
document.addEventListener('DOMContentLoaded', () => {
    // --- 1. DOM Element Cache & State Management ---
    const dom = {
        // Input Form
        analyzeBtn: document.getElementById('analyzeSoarBtn'),
        btnText: document.getElementById('btn-text'),
        inputs: {
            incidentId: document.getElementById('incidentIdInput'),
            threatType: document.getElementById('threatTypeInput'),
            description: document.getElementById('descriptionInput'),
            affectedAssets: document.getElementById('affectedAssetsInput'),
            detectedSource: document.getElementById('detectedSourceInput'),
            severity: document.getElementById('severityInput'),
            organizationId: document.getElementById('organizationIdInput'),
            userQuery: document.getElementById('userQueryInput'),
        },
        // Result Sections
        resultSection: document.getElementById('soarResultSection'),
        resultContent: document.getElementById('soarResultContent'),
        approvalSection: document.getElementById('soarActionApprovalSection'),
        actionDetails: document.getElementById('soarActionDetails'),
        approveBtn: document.getElementById('approveSoarActionBtn'),
        rejectBtn: document.getElementById('rejectSoarActionBtn'),
        // Streaming Modal
        modal: document.getElementById('streaming-modal'),
        modalQueryText: document.getElementById('streaming-query-text'),
        modalContent: document.getElementById('streaming-content'),
        // New Panels
        mcpStatusPanel: document.getElementById('mcpStatusPanel'),
        pipelinePanel: document.getElementById('pipelinePanel'),
        toolLogPanel: document.getElementById('toolLogPanel'),
        toolLogContent: document.getElementById('toolLogContent'),
    };

    const state = {
        isAnalyzing: false,
        currentSessionId: null,
        currentConversationId: null,
        currentApprovalId: null,
        stompClient: null,
        subscriptions: [],
        executedTools: [],
        pendingApprovals: new Map(),
    };

    const API_BASE_URL = '/api/soar';
    const WS_ENDPOINT = '/ws-soar';

    // --- 2. WebSocket Management ---
    const websocket = {
        connect: () => {
            if (state.stompClient && state.stompClient.connected) {
                console.log('WebSocket already connected');
                return Promise.resolve();
            }

            return new Promise((resolve, reject) => {
                const socket = new SockJS(WS_ENDPOINT);
                state.stompClient = Stomp.over(socket);
                
                // Disable debug output in production
                state.stompClient.debug = null;
                
                state.stompClient.connect({}, 
                    frame => {
                        console.log('WebSocket connected');
                        websocket.subscribeToTopics();
                        resolve();
                    },
                    error => {
                        console.error('WebSocket connection failed:', error);
                        reject(error);
                    }
                );
            });
        },

        disconnect: () => {
            if (state.stompClient) {
                // Unsubscribe from all topics
                state.subscriptions.forEach(sub => sub.unsubscribe());
                state.subscriptions = [];
                
                state.stompClient.disconnect(() => {
                    console.log('WebSocket disconnected');
                });
                state.stompClient = null;
            }
        },

        subscribeToTopics: () => {
            // Subscribe to pipeline updates
            const pipelineSub = state.stompClient.subscribe('/topic/soar/pipeline', message => {
                const update = JSON.parse(message.body);
                pipeline.updateStage(update.stage, update.progress, update.message);
            });
            state.subscriptions.push(pipelineSub);

            // Subscribe to tool execution events
            const toolSub = state.stompClient.subscribe('/topic/soar/tools', message => {
                const toolEvent = JSON.parse(message.body);
                toolExecution.handleToolEvent(toolEvent);
            });
            state.subscriptions.push(toolSub);

            // Subscribe to approval events - 비활성화 (soar-websocket-enhanced.js에서 처리)
            // 중복 방지를 위해 주석 처리
            /*
            const approvalSub = state.stompClient.subscribe('/topic/soar/approvals', message => {
                const approvalEvent = JSON.parse(message.body);
                toolExecution.handleApprovalEvent(approvalEvent);
            });
            state.subscriptions.push(approvalSub);
            */

            // Subscribe to simulation events - 필터링된 이벤트만 처리
            const eventSub = state.stompClient.subscribe('/topic/soar/events', message => {
                const event = JSON.parse(message.body);
                // APPROVAL 관련 이벤트는 무시 (중복 방지)
                if (event.type && event.type.includes('APPROVAL')) {
                    console.log('🚫 Ignoring approval event from /topic/soar/events');
                    return;
                }
                handleSimulationEvent(event);
            });
            state.subscriptions.push(eventSub);

            // Subscribe to completion events
            const completeSub = state.stompClient.subscribe('/topic/soar/complete', message => {
                const completeEvent = JSON.parse(message.body);
                handleSimulationComplete(completeEvent);
            });
            state.subscriptions.push(completeSub);

            // Subscribe to error events
            const errorSub = state.stompClient.subscribe('/topic/soar/error', message => {
                const errorEvent = JSON.parse(message.body);
                handleSimulationError(errorEvent);
            });
            state.subscriptions.push(errorSub);
        },

        sendMessage: (destination, payload) => {
            if (state.stompClient && state.stompClient.connected) {
                state.stompClient.send(destination, {}, JSON.stringify(payload));
            } else {
                console.error('WebSocket not connected');
            }
        }
    };

    // --- 3. API Service Layer ---
    const api = {
        // Start simulation with new endpoint
        startSimulation: async (simulationData) => {
            const response = await fetch(`${API_BASE_URL}/simulation/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(simulationData),
            });
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return response.json();
        },

        // Get session status
        getSessionStatus: async (sessionId) => {
            const response = await fetch(`${API_BASE_URL}/simulation/session/${sessionId}`);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return response.json();
        },

        // Submit approval
        submitApproval: async (approvalData) => {
            const response = await fetch(`${API_BASE_URL}/simulation/approve`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(approvalData),
            });
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return response.json();
        },

        // Get MCP server status
        getMcpStatus: async () => {
            const response = await fetch(`${API_BASE_URL}/simulation/mcp-status`);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return response.json();
        }
    };

    // --- 4. MCP Server Status ---
    const mcpStatus = {
        update: async () => {
            try {
                const status = await api.getMcpStatus();
                
                // Update Context7
                const context7El = document.getElementById('mcp-context7');
                mcpStatus.setServerStatus(context7El, status.context7);
                
                // Update Sequential
                const sequentialEl = document.getElementById('mcp-sequential');
                mcpStatus.setServerStatus(sequentialEl, status.sequential);
                
                // Update Magic
                const magicEl = document.getElementById('mcp-magic');
                mcpStatus.setServerStatus(magicEl, status.magic);
                
                // Update Playwright
                const playwrightEl = document.getElementById('mcp-playwright');
                mcpStatus.setServerStatus(playwrightEl, status.playwright);
                
            } catch (error) {
                console.error('Failed to update MCP status:', error);
            }
        },

        setServerStatus: (element, isActive) => {
            if (!element) return;
            
            const indicator = element.querySelector('.mcp-indicator');
            if (isActive) {
                element.classList.add('active');
                element.classList.remove('inactive');
                indicator.classList.add('active');
                indicator.classList.remove('inactive');
            } else {
                element.classList.add('inactive');
                element.classList.remove('active');
                indicator.classList.add('inactive');
                indicator.classList.remove('active');
            }
        }
    };

    // --- 5. Pipeline Progress Management ---
    const pipeline = {
        show: () => {
            dom.pipelinePanel.classList.remove('hidden');
        },

        hide: () => {
            dom.pipelinePanel.classList.add('hidden');
        },

        reset: () => {
            document.querySelectorAll('.pipeline-stage').forEach(stage => {
                stage.classList.remove('active', 'completed');
                const progress = stage.querySelector('.stage-progress');
                if (progress) progress.style.width = '0%';
            });
        },

        updateStage: (stageName, progress, message) => {
            const stageEl = document.querySelector(`[data-stage="${stageName}"]`);
            if (!stageEl) return;

            // Update all previous stages as completed
            const stages = ['PREPROCESSING', 'CONTEXT_RETRIEVAL', 'PROMPT_GENERATION', 
                          'LLM_EXECUTION', 'RESPONSE_PARSING', 'POSTPROCESSING'];
            const currentIndex = stages.indexOf(stageName);
            
            stages.forEach((stage, index) => {
                const el = document.querySelector(`[data-stage="${stage}"]`);
                if (!el) return;
                
                if (index < currentIndex) {
                    el.classList.remove('active');
                    el.classList.add('completed');
                    const progressBar = el.querySelector('.stage-progress');
                    if (progressBar) progressBar.style.width = '100%';
                } else if (index === currentIndex) {
                    el.classList.add('active');
                    el.classList.remove('completed');
                    const progressBar = el.querySelector('.stage-progress');
                    if (progressBar) progressBar.style.width = `${progress}%`;
                }
            });

            // Add to streaming modal if visible
            if (dom.modal.classList.contains('show')) {
                ui.addStreamingStep(message || `${stageName}: ${progress}%`, 'fa-cog fa-spin');
            }
        }
    };

    // --- 6. Tool Execution Management ---
    const toolExecution = {
        show: () => {
            dom.toolLogPanel.classList.remove('hidden');
        },

        hide: () => {
            dom.toolLogPanel.classList.add('hidden');
        },

        reset: () => {
            dom.toolLogContent.innerHTML = '';
            state.executedTools = [];
            state.pendingApprovals.clear();
        },

        addToolEntry: (toolName, status, description, parameters) => {
            const entry = document.createElement('div');
            entry.className = `tool-entry ${status}`;
            entry.innerHTML = `
                <div class="flex justify-between items-start mb-2">
                    <strong>${toolName}</strong>
                    <span class="text-xs px-2 py-1 rounded bg-gray-700">
                        ${status === 'pending' ? '승인 대기' : 
                          status === 'approved' ? '승인됨' : 
                          status === 'rejected' ? '거부됨' : '실행중'}
                    </span>
                </div>
                <div class="text-sm text-gray-400">${description}</div>
                ${parameters ? `<pre class="text-xs mt-2 bg-gray-800 p-2 rounded">${JSON.stringify(parameters, null, 2)}</pre>` : ''}
            `;
            
            dom.toolLogContent.appendChild(entry);
            dom.toolLogContent.scrollTop = dom.toolLogContent.scrollHeight;
            
            return entry;
        },

        handleToolEvent: (event) => {
            console.log('Tool event:', event);
            
            if (event.requiresApproval) {
                // Add pending approval entry
                const entry = toolExecution.addToolEntry(
                    event.toolName,
                    'pending',
                    event.description,
                    event.parameters
                );
                
                state.pendingApprovals.set(event.toolName, {
                    entry,
                    sessionId: event.sessionId,
                    approvalId: event.approvalId || event.toolName
                });
                
                // Show approval dialog
                toolExecution.showApprovalDialog(event);
            } else {
                // Add executed tool entry
                toolExecution.addToolEntry(
                    event.toolName,
                    'approved',
                    event.description,
                    event.parameters
                );
                state.executedTools.push(event.toolName);
            }
        },

        handleApprovalEvent: (event) => {
            console.log('Approval event:', event);
            
            const pending = state.pendingApprovals.get(event.toolName);
            if (pending && pending.entry) {
                // Update the entry status
                pending.entry.classList.remove('pending');
                pending.entry.classList.add(event.approved ? 'approved' : 'rejected');
                
                const statusSpan = pending.entry.querySelector('span');
                if (statusSpan) {
                    statusSpan.textContent = event.approved ? '승인됨' : '거부됨';
                }
                
                state.pendingApprovals.delete(event.toolName);
            }
            
            if (event.approved) {
                state.executedTools.push(event.toolName);
            }
        },

        showApprovalDialog: (toolEvent) => {
            // For now, auto-approve for simulation
            // In production, show a proper modal dialog
            setTimeout(() => {
                const approved = confirm(`도구 실행 승인: ${toolEvent.toolName}\n\n${toolEvent.description}\n\n승인하시겠습니까?`);
                
                api.submitApproval({
                    sessionId: state.currentSessionId,
                    approvalId: toolEvent.approvalId || toolEvent.toolName,
                    toolName: toolEvent.toolName,
                    approved: approved,
                    reason: approved ? 'User approved' : 'User rejected'
                }).catch(error => {
                    console.error('Approval submission failed:', error);
                    window.showToast('승인 처리 실패', 'error');
                });
            }, 1000);
        }
    };

    // --- 7. UI Rendering & Manipulation ---
    const ui = {
        setLoading: (isLoading) => {
            state.isAnalyzing = isLoading;
            dom.analyzeBtn.disabled = isLoading;
            if (isLoading) {
                dom.btnText.innerHTML = `<span class="loading-spinner"></span> AI 파이프라인 실행 중...`;
            } else {
                dom.btnText.innerHTML = `<i class="fas fa-robot mr-3"></i>AI + MCP + SOAR 시뮬레이션 시작`;
            }
        },

        showStreamingModal: (query) => {
            dom.modalQueryText.textContent = query;
            dom.modalContent.innerHTML = '';
            ui.addStreamingStep('AI + MCP + SOAR 통합 워크플로우를 시작합니다...', 'fa-play-circle');
            dom.modal.classList.add('show');
        },

        hideStreamingModal: () => {
            dom.modal.classList.remove('show');
        },

        addStreamingStep: (text, iconClass = 'fa-cog fa-spin', isComplete = false) => {
            const step = document.createElement('div');
            step.className = `streaming-step ${isComplete ? 'streaming-complete' : ''}`;
            step.innerHTML = `<i class="fas ${iconClass} mr-2"></i>${text}`;
            dom.modalContent.appendChild(step);
            dom.modalContent.scrollTop = dom.modalContent.scrollHeight;
        },

        renderResults: (response) => {
            let finalHtml = `<strong>세션 ID:</strong> ${state.currentSessionId}<br>`;
            finalHtml += `<strong>대화 ID:</strong> ${state.currentConversationId}<br><br>`;
            
            if (response.finalResponse) {
                finalHtml += `<strong>AI 분석 결과:</strong><pre class="bg-gray-800 p-2 rounded mt-1 text-xs">${response.finalResponse}</pre><br>`;
            }
            
            if (state.executedTools.length > 0) {
                finalHtml += `<strong>실행된 도구:</strong><ul class="list-disc list-inside mt-1">`;
                state.executedTools.forEach(tool => {
                    finalHtml += `<li>${tool}</li>`;
                });
                finalHtml += `</ul>`;
            }
            
            dom.resultContent.innerHTML = finalHtml;
            dom.resultSection.classList.remove('hidden');
        }
    };

    // --- 8. Event Handlers ---
    const handleSimulationEvent = (event) => {
        console.log('Simulation event:', event);
        
        if (event.eventType === 'SIMULATION_STARTED') {
            ui.addStreamingStep('시뮬레이션이 성공적으로 시작되었습니다', 'fa-check-circle');
        }
    };

    const handleSimulationComplete = (event) => {
        console.log('Simulation complete:', event);
        
        ui.addStreamingStep('AI + MCP + SOAR 워크플로우가 완료되었습니다!', 'fa-flag-checkered', true);
        
        setTimeout(() => {
            ui.hideStreamingModal();
            ui.setLoading(false);
            ui.renderResults({
                finalResponse: `시뮬레이션 완료\n실행 시간: ${event.durationMs}ms\n실행된 도구: ${event.executedTools.join(', ')}`,
                executedTools: event.executedTools
            });
        }, 2000);
    };

    const handleSimulationError = (event) => {
        console.error('Simulation error:', event);
        
        ui.addStreamingStep(`오류 발생: ${event.error}`, 'fa-exclamation-circle', true);
        window.showToast('시뮬레이션 오류: ' + event.error, 'error');
        
        setTimeout(() => {
            ui.hideStreamingModal();
            ui.setLoading(false);
        }, 2000);
    };

    const startSoarSimulation = async () => {
        if (state.isAnalyzing) return;

        const simulationData = {
            incidentId: dom.inputs.incidentId.value || `INC-${Date.now()}`,
            threatType: dom.inputs.threatType.value || 'Unknown Threat',
            description: dom.inputs.description.value,
            affectedAssets: dom.inputs.affectedAssets.value.split(',').map(s => s.trim()).filter(s => s),
            detectedSource: dom.inputs.detectedSource.value || 'Manual',
            severity: dom.inputs.severity.value,
            organizationId: dom.inputs.organizationId.value || 'org_default',
            userQuery: dom.inputs.userQuery.value,
            metadata: {
                timestamp: new Date().toISOString(),
                source: 'Web UI'
            }
        };

        if (!simulationData.description) {
            window.showToast('상세 설명은 필수입니다.', 'error');
            return;
        }

        ui.setLoading(true);
        dom.resultSection.classList.add('hidden');
        dom.approvalSection.classList.add('hidden');
        
        // Reset panels
        pipeline.reset();
        toolExecution.reset();
        
        // Show panels
        pipeline.show();
        toolExecution.show();
        
        ui.showStreamingModal(simulationData.userQuery || simulationData.description);

        try {
            // Connect WebSocket first
            await websocket.connect();
            
            // Update MCP status
            await mcpStatus.update();
            
            // Start simulation
            const response = await api.startSimulation(simulationData);
            
            state.currentSessionId = response.sessionId;
            state.currentConversationId = response.conversationId;
            
            ui.addStreamingStep(`세션 시작: ${response.sessionId}`, 'fa-info-circle');
            
            // The rest will be handled by WebSocket events
            
        } catch (error) {
            console.error('Simulation start failed:', error);
            window.showToast('시뮬레이션 시작 실패: ' + error.message, 'error');
            ui.setLoading(false);
            ui.hideStreamingModal();
        }
    };

    // --- 9. Initializer ---
    const init = () => {
        // Bind event handlers
        dom.analyzeBtn.addEventListener('click', startSoarSimulation);
        
        if (dom.approveBtn) {
            dom.approveBtn.addEventListener('click', () => {
                if (state.currentApprovalId) {
                    api.submitApproval({
                        sessionId: state.currentSessionId,
                        approvalId: state.currentApprovalId,
                        toolName: 'Unknown',
                        approved: true,
                        reason: 'Approved by user'
                    });
                }
            });
        }
        
        if (dom.rejectBtn) {
            dom.rejectBtn.addEventListener('click', () => {
                if (state.currentApprovalId) {
                    api.submitApproval({
                        sessionId: state.currentSessionId,
                        approvalId: state.currentApprovalId,
                        toolName: 'Unknown',
                        approved: false,
                        reason: 'Rejected by user'
                    });
                }
            });
        }
        
        // Initial MCP status check
        mcpStatus.update();
        
        // Cleanup on page unload
        window.addEventListener('beforeunload', () => {
            websocket.disconnect();
        });
    };

    init();
});