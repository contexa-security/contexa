/**
 * SOAR WebSocket Integration Test Suite
 * 
 * 완전한 WebSocket 승인 시스템 통합 테스트
 */

class SoarIntegrationTest {
    constructor() {
        this.testResults = [];
        this.currentTest = null;
    }

    /**
     * 모든 테스트 실행
     */
    async runAllTests() {
        console.log('🧪 ===========================================');
        console.log('🧪 SOAR INTEGRATION TEST SUITE');
        console.log('🧪 시작 시간:', new Date().toLocaleString());
        console.log('🧪 ===========================================');

        const tests = [
            () => this.testWebSocketConnection(),
            () => this.testApprovalModalCreation(),
            () => this.testApprovalHandlerInitialization(),
            () => this.testEventListenerRegistration(),
            () => this.testDirectModalDisplay(),
            () => this.testWebSocketMessageReception(),
            () => this.testAPITriggerApproval(),
            () => this.testApprovalResponseHandling(),
            () => this.testErrorRecovery(),
            () => this.testFullIntegration()
        ];

        for (const test of tests) {
            try {
                await test();
                await this.delay(1000); // 테스트 간 지연
            } catch (error) {
                this.recordResult(false, `테스트 실패: ${error.message}`);
            }
        }

        this.printTestReport();
    }

    /**
     * Test 1: WebSocket 연결 테스트
     */
    async testWebSocketConnection() {
        this.startTest('WebSocket 연결');
        
        try {
            const websocket = new EnhancedWebSocketClient('/ws-soar');
            
            await new Promise((resolve, reject) => {
                websocket.onConnect = () => {
                    this.recordResult(true, 'WebSocket 연결 성공');
                    resolve();
                };
                
                websocket.onError = (error) => {
                    reject(error);
                };
                
                websocket.connect();
                
                // 10초 타임아웃
                setTimeout(() => reject(new Error('연결 타임아웃')), 10000);
            });
            
            // 연결 상태 확인
            if (websocket.isConnected()) {
                this.recordResult(true, 'WebSocket 연결 상태 확인됨');
                
                // 구독 확인
                const subscriptions = Array.from(websocket.subscriptions.keys());
                if (subscriptions.includes('/topic/soar/approvals')) {
                    this.recordResult(true, '/topic/soar/approvals 구독 확인됨');
                } else {
                    this.recordResult(false, '/topic/soar/approvals 구독 실패');
                }
            }
            
            // 정리
            websocket.disconnect();
            
        } catch (error) {
            this.recordResult(false, `WebSocket 연결 실패: ${error.message}`);
        }
    }

    /**
     * Test 2: 승인 모달 생성 테스트
     */
    async testApprovalModalCreation() {
        this.startTest('승인 모달 생성');
        
        try {
            const modal = new SoarApprovalModal();
            
            if (modal) {
                this.recordResult(true, 'SoarApprovalModal 인스턴스 생성 성공');
                
                // 스타일 확인
                const styles = document.getElementById('soar-approval-modal-styles');
                if (styles) {
                    this.recordResult(true, '모달 스타일 로드됨');
                } else {
                    this.recordResult(false, '모달 스타일 누락');
                }
            } else {
                this.recordResult(false, '모달 생성 실패');
            }
        } catch (error) {
            this.recordResult(false, `모달 생성 오류: ${error.message}`);
        }
    }

    /**
     * Test 3: ApprovalHandler 초기화 테스트
     */
    async testApprovalHandlerInitialization() {
        this.startTest('ApprovalHandler 초기화');
        
        try {
            const websocket = new EnhancedWebSocketClient('/ws-soar');
            const modal = new SoarApprovalModal();
            
            // WebSocket 연결
            await new Promise((resolve) => {
                websocket.onConnect = resolve;
                websocket.connect();
            });
            
            // Handler 초기화
            const handler = new SoarApprovalHandler();
            const result = handler.initialize(websocket, modal);
            
            if (result) {
                this.recordResult(true, 'ApprovalHandler 초기화 성공');
            } else {
                this.recordResult(false, 'ApprovalHandler 초기화 실패');
            }
            
            // 정리
            websocket.disconnect();
            
        } catch (error) {
            this.recordResult(false, `Handler 초기화 오류: ${error.message}`);
        }
    }

    /**
     * Test 4: 이벤트 리스너 등록 테스트
     */
    async testEventListenerRegistration() {
        this.startTest('이벤트 리스너 등록');
        
        try {
            const websocket = new EnhancedWebSocketClient('/ws-soar');
            
            // 리스너 등록
            let listenerCalled = false;
            websocket.on('approvals', () => {
                listenerCalled = true;
            });
            
            // 이벤트 트리거
            websocket.notifyListeners('approvals', { test: true });
            
            if (listenerCalled) {
                this.recordResult(true, 'approvals 이벤트 리스너 동작 확인');
            } else {
                this.recordResult(false, 'approvals 이벤트 리스너 동작 실패');
            }
            
        } catch (error) {
            this.recordResult(false, `리스너 등록 오류: ${error.message}`);
        }
    }

    /**
     * Test 5: 직접 모달 표시 테스트
     */
    async testDirectModalDisplay() {
        this.startTest('직접 모달 표시');
        
        try {
            const modal = new SoarApprovalModal();
            
            const testRequest = {
                approvalId: 'TEST-' + Date.now(),
                toolName: '테스트 도구',
                description: '통합 테스트를 위한 승인 요청',
                riskLevel: 'HIGH'
            };
            
            // 모달 표시 (Promise)
            const promise = modal.show(testRequest);
            
            // DOM 확인 (짧은 지연 후)
            await this.delay(100);
            
            const modalElement = document.querySelector('.soar-approval-modal-overlay');
            if (modalElement) {
                this.recordResult(true, '모달이 DOM에 추가됨');
                
                // 모달 닫기
                modalElement.remove();
                modal.activeModal = null;
            } else {
                this.recordResult(false, '모달이 DOM에 추가되지 않음');
            }
            
        } catch (error) {
            this.recordResult(false, `모달 표시 오류: ${error.message}`);
        }
    }

    /**
     * Test 6: WebSocket 메시지 수신 테스트
     */
    async testWebSocketMessageReception() {
        this.startTest('WebSocket 메시지 수신');
        
        try {
            const websocket = new EnhancedWebSocketClient('/ws-soar');
            const modal = new SoarApprovalModal();
            
            // 연결
            await new Promise((resolve) => {
                websocket.onConnect = resolve;
                websocket.connect();
            });
            
            // Handler 설정
            const handler = new SoarApprovalHandler();
            handler.initialize(websocket, modal);
            
            // 메시지 수신 확인
            let messageReceived = false;
            websocket.on('approvals', (data) => {
                messageReceived = true;
                console.log('메시지 수신:', data);
            });
            
            // 시뮬레이션 메시지
            websocket.notifyListeners('approvals', {
                type: 'APPROVAL_REQUEST',
                approvalId: 'SIM-' + Date.now()
            });
            
            if (messageReceived) {
                this.recordResult(true, 'WebSocket 메시지 수신 확인');
            } else {
                this.recordResult(false, 'WebSocket 메시지 수신 실패');
            }
            
            // 정리
            websocket.disconnect();
            
        } catch (error) {
            this.recordResult(false, `메시지 수신 오류: ${error.message}`);
        }
    }

    /**
     * Test 7: API 트리거 승인 테스트
     */
    async testAPITriggerApproval() {
        this.startTest('API 트리거 승인');
        
        try {
            // WebSocket 설정
            const websocket = new EnhancedWebSocketClient('/ws-soar');
            const modal = new SoarApprovalModal();
            const handler = new SoarApprovalHandler();
            
            // 연결 및 초기화
            await new Promise((resolve) => {
                websocket.onConnect = () => {
                    handler.initialize(websocket, modal);
                    resolve();
                };
                websocket.connect();
            });
            
            // API 호출
            const response = await fetch('/api/test/websocket/trigger-approval?riskLevel=HIGH', {
                method: 'POST'
            });
            
            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    this.recordResult(true, 'API 승인 요청 성공');
                    
                    // 모달 확인 (약간의 지연)
                    await this.delay(500);
                    
                    const modalElement = document.querySelector('.soar-approval-modal-overlay');
                    if (modalElement) {
                        this.recordResult(true, 'API 트리거로 모달 표시됨');
                        modalElement.remove();
                    } else {
                        this.recordResult(false, 'API 트리거로 모달 표시 실패');
                    }
                } else {
                    this.recordResult(false, `API 요청 실패: ${result.error}`);
                }
            } else {
                this.recordResult(false, `API 응답 오류: ${response.status}`);
            }
            
            // 정리
            websocket.disconnect();
            
        } catch (error) {
            this.recordResult(false, `API 테스트 오류: ${error.message}`);
        }
    }

    /**
     * Test 8: 승인 응답 처리 테스트
     */
    async testApprovalResponseHandling() {
        this.startTest('승인 응답 처리');
        
        try {
            const modal = new SoarApprovalModal();
            
            const testRequest = {
                approvalId: 'RESP-' + Date.now(),
                toolName: '응답 테스트',
                riskLevel: 'MEDIUM'
            };
            
            // 모달 표시 및 응답 처리
            const responsePromise = modal.show(testRequest);
            
            // 자동 승인 시뮬레이션
            await this.delay(100);
            const approveBtn = document.querySelector('.soar-approval-btn-approve');
            if (approveBtn) {
                approveBtn.click();
                
                const response = await responsePromise;
                if (response.approved) {
                    this.recordResult(true, '승인 응답 처리 성공');
                } else {
                    this.recordResult(false, '승인 응답이 거부됨');
                }
            } else {
                this.recordResult(false, '승인 버튼을 찾을 수 없음');
                // 모달 정리
                const modalElement = document.querySelector('.soar-approval-modal-overlay');
                if (modalElement) modalElement.remove();
            }
            
        } catch (error) {
            this.recordResult(false, `응답 처리 오류: ${error.message}`);
        }
    }

    /**
     * Test 9: 오류 복구 테스트
     */
    async testErrorRecovery() {
        this.startTest('오류 복구');
        
        try {
            const websocket = new EnhancedWebSocketClient('/ws-soar');
            
            // 재연결 시도 확인
            let reconnectAttempted = false;
            websocket.on('error', () => {
                reconnectAttempted = true;
            });
            
            // 연결 오류 시뮬레이션
            websocket.handleConnectionError(new Error('Test error'));
            
            if (reconnectAttempted || websocket.reconnectAttempts > 0) {
                this.recordResult(true, '오류 시 재연결 시도 확인');
            } else {
                this.recordResult(false, '오류 복구 메커니즘 실패');
            }
            
        } catch (error) {
            this.recordResult(false, `오류 복구 테스트 실패: ${error.message}`);
        }
    }

    /**
     * Test 10: 전체 통합 테스트
     */
    async testFullIntegration() {
        this.startTest('전체 통합');
        
        try {
            // 전체 시스템 초기화 (soar-analysis-enhanced 방식)
            if (window.soarEnhanced) {
                const status = window.soarEnhanced.getSystemStatus();
                
                if (status.websocket) {
                    this.recordResult(true, 'WebSocket 연결 확인');
                } else {
                    this.recordResult(false, 'WebSocket 연결 안됨');
                }
                
                if (status.approvalQueue !== undefined) {
                    this.recordResult(true, '승인 큐 시스템 확인');
                } else {
                    this.recordResult(false, '승인 큐 시스템 없음');
                }
                
                // 수동 테스트
                window.soarEnhanced.testApprovalModal();
                
                await this.delay(100);
                const modalElement = document.querySelector('.soar-approval-modal-overlay');
                if (modalElement) {
                    this.recordResult(true, '통합 시스템에서 모달 표시 성공');
                    modalElement.remove();
                } else {
                    this.recordResult(false, '통합 시스템에서 모달 표시 실패');
                }
                
            } else {
                this.recordResult(false, 'soarEnhanced 시스템이 초기화되지 않음');
            }
            
        } catch (error) {
            this.recordResult(false, `통합 테스트 오류: ${error.message}`);
        }
    }

    // === 유틸리티 메서드 ===

    startTest(name) {
        this.currentTest = {
            name,
            results: [],
            startTime: Date.now()
        };
        console.log(`\n🧪 테스트: ${name}`);
        console.log('━'.repeat(50));
    }

    recordResult(success, message) {
        const result = {
            success,
            message,
            timestamp: Date.now()
        };
        
        if (this.currentTest) {
            this.currentTest.results.push(result);
        }
        
        if (success) {
            console.log(`${message}`);
        } else {
            console.error(`${message}`);
        }
        
        // 전체 결과에도 추가
        this.testResults.push({
            test: this.currentTest?.name || 'Unknown',
            ...result
        });
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    printTestReport() {
        console.log('\n');
        console.log('🧪 ===========================================');
        console.log('🧪 테스트 결과 요약');
        console.log('🧪 ===========================================');
        
        const totalTests = this.testResults.length;
        const passedTests = this.testResults.filter(r => r.success).length;
        const failedTests = totalTests - passedTests;
        const passRate = ((passedTests / totalTests) * 100).toFixed(1);
        
        console.log(`📊 전체 테스트: ${totalTests}`);
        console.log(`성공: ${passedTests}`);
        console.log(`실패: ${failedTests}`);
        console.log(`📈 성공률: ${passRate}%`);
        
        if (failedTests > 0) {
            console.log('\n실패한 테스트:');
            this.testResults.filter(r => !r.success).forEach(r => {
                console.log(`  ${r.test}: ${r.message}`);
            });
        }
        
        console.log('\n🧪 테스트 완료 시간:', new Date().toLocaleString());
        console.log('🧪 ===========================================');
        
        // 결과 반환
        return {
            total: totalTests,
            passed: passedTests,
            failed: failedTests,
            passRate,
            results: this.testResults
        };
    }
}

// 전역으로 사용 가능하도록 설정
if (typeof window !== 'undefined') {
    window.SoarIntegrationTest = SoarIntegrationTest;
    
    // 자동 테스트 실행 함수
    window.runSoarTests = async function() {
        const tester = new SoarIntegrationTest();
        return await tester.runAllTests();
    };
    
    console.log('SOAR Integration Test Suite loaded');
    console.log('Run tests with: window.runSoarTests()');
}