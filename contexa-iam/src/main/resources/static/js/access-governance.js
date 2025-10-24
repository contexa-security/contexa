/**
 * Access Governance Analysis JavaScript
 * 
 * 시스템 전체 권한 분포와 사용 현황을 분석하여 잠재적 이상 징후를 탐지하는 AI 기능
 * 예방적 보안을 구현하여 위협이 발생하기 전에 시스템이 가진 잠재적 위험 요소를 AI가 미리 찾아내어 보고
 */

// 전역 변수
let selectedAnalysisType = null;
let currentEventSource = null;
let allUsersAndGroups = { users: [], groups: [] };
let selectedItems = new Set();

// === 전체보기(FullScreen) 기능 ===
let cytoscapeInstance = null;
let fullscreenCytoscapeInstance = null;
let currentZoomLevel = 1.0;

// 페이지 로드 시 초기화
document.addEventListener('DOMContentLoaded', function() {
    console.log('Access Governance Analysis 페이지 로드됨');
    loadAnalysisTypes();
    loadUsersAndGroups();
    bindUserGroupEventListeners();
    
    // 전체보기 버튼 이벤트 리스너
    const fullscreenBtn = document.getElementById('diagram-fullscreen-btn');
    if (fullscreenBtn) {
        fullscreenBtn.addEventListener('click', showFullscreenDiagram);
    }
});

/**
 * 사용자/그룹 이벤트 리스너 바인딩
 */
function bindUserGroupEventListeners() {
    // 검색 이벤트 - studio.js와 동일하게 즉시 실행
    const searchInput = document.getElementById('user-group-search');
    if (searchInput) {
        searchInput.addEventListener('input', function(e) {
            filterUsersAndGroups(e.target.value);
        });
    }
}

/**
 * 사용자/그룹 로드
 */
async function loadUsersAndGroups() {
    try {
        console.log('사용자/그룹 로드 중...');
        
        const response = await fetch('/api/workbench/metadata/subjects');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        allUsersAndGroups = {
            users: data.users || [],
            groups: data.groups || []
        };
        
        renderUsersAndGroups(allUsersAndGroups);
        console.log('사용자/그룹 로드 완료:', allUsersAndGroups.users.length + '명, ' + allUsersAndGroups.groups.length + '개 그룹');
        
    } catch (error) {
        console.error('사용자/그룹 로드 실패:', error);
        showError('사용자/그룹을 불러오는데 실패했습니다: ' + error.message);
    }
}

/**
 * 사용자/그룹 렌더링
 */
function renderUsersAndGroups(data) {
    console.log('renderUsersAndGroups 호출됨:', data);
    
    const container = document.getElementById('user-group-list');
    if (!container) {
        console.error('user-group-list 컨테이너를 찾을 수 없음');
        return;
    }
    
    console.log('컨테이너 찾음:', container);
    
    const sections = {
        '사용자': { items: data.users, type: 'USER', icon: 'fa-user' },
        '그룹': { items: data.groups, type: 'GROUP', icon: 'fa-users' },
    };
    
    console.log('📋 섹션 구성:', sections);
    
    const html = Object.entries(sections)
        .map(([title, { items, type, icon }]) => createAccordionSection(title, items, type, icon))
        .join('');
    
    container.innerHTML = html;
    
    bindAccordionEvents();
}

/**
 * 아코디언 섹션 생성
 */
function createAccordionSection(title, items, type, icon) {
    console.log(`createAccordionSection: ${title}`, items);
    
    const contentHtml = items?.length
        ? items.map(item => createItemHtml(item, type, icon)).join('')
        : '<div class="p-2 text-xs text-slate-400">항목이 없습니다.</div>';
    
    return `
        <div class="accordion">
            <div class="accordion-header">
                <span class="font-bold">${title}</span>
                <i class="fas fa-chevron-down accordion-icon"></i>
            </div>
            <div class="accordion-content">
                ${contentHtml}
            </div>
        </div>
    `;
}

/**
 * 아이템 HTML 생성
 */
function createItemHtml(item, type, icon) {
    const isSelected = selectedItems.has(`${type}_${item.id}`);
    const selectedClass = isSelected ? 'selected' : '';
    
    return `
        <div class="explorer-item ${selectedClass}" 
             data-id="${item.id}" 
             data-type="${type}" 
             data-name="${item.name}" 
             data-description="${item.description || ''}">
            <div class="item-icon">
                <i class="fas ${icon}"></i>
            </div>
            <div class="item-text">
                <div class="item-name">${item.name}</div>
                <div class="item-description" title="${item.description || ''}">${item.description || ''}</div>
            </div>
        </div>
    `;
}

/**
 * 아코디언 이벤트 바인딩
 */
function bindAccordionEvents() {
    const accordionHeaders = document.querySelectorAll('.accordion-header');
    accordionHeaders.forEach(header => {
        header.addEventListener('click', function() {
            const accordion = this.closest('.accordion');
            const content = accordion.querySelector('.accordion-content');
            const icon = this.querySelector('.accordion-icon');
            
            // 다른 아코디언 닫기
            document.querySelectorAll('.accordion-content').forEach(content => {
                content.style.display = 'none';
            });
            document.querySelectorAll('.accordion-icon').forEach(icon => {
                icon.style.transform = 'rotate(0deg)';
            });
            
            // 현재 아코디언 토글
            if (content.style.display === 'none' || !content.style.display) {
                content.style.display = 'block';
                icon.style.transform = 'rotate(180deg)';
            } else {
                content.style.display = 'none';
                icon.style.transform = 'rotate(0deg)';
            }
        });
    });
    
    // 🔥 모든 아코디언을 기본적으로 열기
    const accordions = document.querySelectorAll('.accordion');
    accordions.forEach((accordion, index) => {
        const content = accordion.querySelector('.accordion-content');
        const icon = accordion.querySelector('.accordion-icon');
        if (content) {
            content.style.display = 'block';
            icon.style.transform = 'rotate(180deg)';
        }
    });
    
    // 아이템 클릭 이벤트
    const explorerItems = document.querySelectorAll('.explorer-item');
    explorerItems.forEach(item => {
        item.addEventListener('click', function() {
            const id = this.dataset.id;
            const type = this.dataset.type;
            const name = this.dataset.name;
            const key = `${type}_${id}`;
            
            if (selectedItems.has(key)) {
                selectedItems.delete(key);
                this.classList.remove('selected');
            } else {
                selectedItems.add(key);
                this.classList.add('selected');
            }
            
            updateSelectedItemsDisplay();
        });
    });
}

/**
 * 선택된 항목 표시 업데이트
 */
function updateSelectedItemsDisplay() {
    const container = document.getElementById('selected-items');
    if (!container) return;
    
    container.innerHTML = '';
    
    selectedItems.forEach(key => {
        const [type, id] = key.split('_');
        const items = type === 'USER' ? allUsersAndGroups.users : allUsersAndGroups.groups;
        const item = items.find(item => item.id == id);
        
        if (item) {
            const itemDiv = document.createElement('div');
            itemDiv.className = 'flex items-center justify-between p-2 bg-slate-800 rounded-lg mb-2';
            itemDiv.innerHTML = `
                <div class="flex items-center gap-2">
                    <i class="fas ${type === 'USER' ? 'fa-user' : 'fa-users'} text-indigo-400"></i>
                    <span class="text-sm text-slate-300">${item.name}</span>
                </div>
                <button type="button" class="text-slate-400 hover:text-red-400" onclick="removeSelectedItem('${key}')">
                    <i class="fas fa-times"></i>
                </button>
            `;
            container.appendChild(itemDiv);
        }
    });
}

/**
 * 선택된 항목 제거
 */
function removeSelectedItem(key) {
    selectedItems.delete(key);
    
    // UI에서 선택 상태 제거
    const [type, id] = key.split('_');
    const itemElement = document.querySelector(`.explorer-item[data-type="${type}"][data-id="${id}"]`);
    if (itemElement) {
        itemElement.classList.remove('selected');
    }
    
    updateSelectedItemsDisplay();
}

/**
 * 사용자/그룹 필터링
 */
function filterUsersAndGroups(searchTerm) {
    const searchLower = searchTerm.toLowerCase();
    const explorerItems = document.querySelectorAll('.explorer-item');
    
    explorerItems.forEach(item => {
        const name = item.dataset.name.toLowerCase();
        const description = (item.dataset.description || '').toLowerCase();
        
        if (name.includes(searchLower) || description.includes(searchLower)) {
            item.style.display = 'flex';
        } else {
            item.style.display = 'none';
        }
    });
}

/**
 * debounce 함수
 */
function debounce(func, delay) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), delay);
    };
}

/**
 * 분석 유형 로드
 */
async function loadAnalysisTypes() {
    try {
        console.log('분석 유형 로드 중...');
        
        const response = await fetch('/api/ai/access-governance/analysis-types');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const analysisTypes = await response.json();
        displayAnalysisTypes(analysisTypes);
        
        console.log('분석 유형 로드 완료:', analysisTypes.length + '개');
        
    } catch (error) {
        console.error('분석 유형 로드 실패:', error);
        showError('분석 유형을 불러오는데 실패했습니다: ' + error.message);
    }
}

/**
 * 분석 유형 표시
 */
function displayAnalysisTypes(analysisTypes) {
    const container = document.getElementById('analysisTypes');
    if (!container) return;
    
    container.innerHTML = '';
    
    analysisTypes.forEach(type => {
        const card = document.createElement('div');
        card.className = 'bg-slate-800 rounded-lg p-4 cursor-pointer hover:bg-slate-700 transition-colors';
        card.onclick = () => selectAnalysisType(type.id);
        card.innerHTML = `
            <div class="text-center">
                <i class="${type.icon}" style="color: ${type.color}; font-size: 1.5rem;"></i>
                <h6 class="text-slate-200 font-semibold mt-2">${type.name}</h6>
                <p class="text-xs text-slate-400 mt-1">${type.description}</p>
            </div>
        `;
        container.appendChild(card);
    });
}

/**
 * 분석 유형 선택
 */
function selectAnalysisType(typeId) {
    // 기존 선택 해제
    document.querySelectorAll('#analysisTypes > div').forEach(card => {
        card.classList.remove('ring-2', 'ring-indigo-500');
    });
    
    // 새로운 선택 표시
    event.currentTarget.classList.add('ring-2', 'ring-indigo-500');
    
    selectedAnalysisType = typeId;
    console.log('분석 유형 선택됨:', typeId);
}

/**
 * 분석 유형 새로고침
 */
function refreshAnalysisTypes() {
    console.log('분석 유형 새로고침 중...');
    loadAnalysisTypes();
}

/**
 * 동기 분석 실행
 */
async function analyze() {
    if (!validateAnalysisRequest()) {
        return;
    }
    
    try {
        console.log('권한 거버넌스 분석 시작...');
        
        // UI 상태 변경
        showLoading();
        hideResults();
        
        // 요청 데이터 구성
        const requestData = buildAnalysisRequest();
        
        // API 호출
        const response = await fetch('/api/ai/access-governance/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestData)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        displayAnalysisResult(result);
        
        console.log('권한 거버넌스 분석 완료');
        
    } catch (error) {
        console.error('권한 거버넌스 분석 실패:', error);
        showError('분석 중 오류가 발생했습니다: ' + error.message);
    } finally {
        hideLoading();
    }
}

/**
 * 스트리밍 분석 실행
 */
async function analyzeStream() {
    if (!validateAnalysisRequest()) {
        return;
    }
    
    try {
        console.log('스트리밍 권한 거버넌스 분석 시작...');
        
        // 기존 스트리밍 연결 종료
        if (currentEventSource) {
            currentEventSource.close();
        }
        
        // 요청 데이터 구성
        const requestData = buildAnalysisRequest();
        
        // 🎥 스트리밍 모달 표시 (studio.html과 동일한 방식)
        showStreamingProgressModal(requestData.query);
        await new Promise(resolve => setTimeout(resolve, 100)); // DOM 추가 완료 대기
        
        // 🔥 기존 SecurityCopilotClient와 동일한 방식으로 수정
        const response = await fetch('/api/ai/access-governance/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'text/event-stream',
                'Cache-Control': 'no-cache'
            },
            body: JSON.stringify(requestData)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let allDataBuffer = ''; // 🔥 모든 데이터를 저장하는 버퍼
        let isStreaming = true;
        
        console.log('🌊 스트리밍 연결 시작 - 데이터 대기 중...');
        addStreamingStep('권한 거버넌스 분석을 시작합니다...');
        addStreamingStep('📡 서버와 연결하고 있습니다...');
        
        while (isStreaming) {
            const { done, value } = await reader.read();
            
            if (done) {
                console.log('🌊 스트리밍 연결 종료');
                isStreaming = false;
                break;
            }
            
            const chunk = decoder.decode(value, { stream: true });
            buffer += chunk;
            
            // 🔥 기존 방식과 동일한 라인 처리
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';
            
            for (const line of lines) {
                if (line.trim() === '') continue;
                
                console.log('[DEBUG] 받은 라인:', JSON.stringify(line));
                
                let data = line;
                
                // data: 프리픽스 제거
                if (line.startsWith('data:')) {
                    data = line.slice(5).trim();
                    console.log('[DEBUG] data: 프리픽스 제거 후:', JSON.stringify(data));
                }
                
                // event: 라인은 무시
                if (line.startsWith('event:')) {
                    console.log('🎯 [DEBUG] event 라인 무시:', line);
                    continue;
                }
                
                // 🔥 정리된 데이터만 allDataBuffer에 누적 (ai-studio.js와 동일)
                allDataBuffer += data;
                
                // 🔥 완료 신호 처리
                if (data === '[DONE]' || data === 'COMPLETE') {
                    console.log('🌊 스트리밍 완료 신호 수신');
                    isStreaming = false;
                    addStreamingStep('분석이 완료되었습니다.');
                    
                    // 🔥 studio.html과 동일한 방식으로 최종 응답 처리
                    processFinalResponse(allDataBuffer);
                    break;
                }
                
                // 🔥 진단 과정 내용만 모달창에 출력 (기술적 데이터 필터링)
                if (data && data.trim() && 
                    data !== '[DONE]' && 
                    data !== 'COMPLETE' && 
                    !data.startsWith('###FINAL_RESPONSE###')) {
                    
                    console.log('[DEBUG] 모달창 출력:', JSON.stringify(data));
                    addStreamingStep(data);
                    console.log('[DEBUG] 모달창 출력 완료');
                }
            }
        }
        
    } catch (error) {
        console.error('스트리밍 권한 거버넌스 분석 실패:', error);
        showError('스트리밍 분석 중 오류가 발생했습니다: ' + error.message);
        hideStreamingProgressModal();
    }
}

/**
 * 🔥 studio.html과 동일한 최종 응답 처리
 */
function processFinalResponse(fullData) {
    console.log('📊 [FINAL-PARSING] JSON 파싱 시작');
    console.log('전체 데이터 길이:', fullData.length);

    const markerIndex = fullData.indexOf('###FINAL_RESPONSE###');
    if (markerIndex === -1) {
        console.error('FINAL_RESPONSE 마커를 찾을 수 없음');
        handleJsonParseError('');
        return;
    }

    const marker = '###FINAL_RESPONSE###';
    let jsonData = fullData.substring(markerIndex + marker.length);

    // 🔥 중복 제거: JSON 안에 ###FINAL_RESPONSE### 마커가 또 있는 경우 첫 번째만 사용
    const duplicateMarkerIndex = jsonData.indexOf('###FINAL_RESPONSE###');
    if (duplicateMarkerIndex !== -1) {
        console.warn('중복된 FINAL_RESPONSE 마커 감지 - 첫 번째만 사용');
        jsonData = jsonData.substring(0, duplicateMarkerIndex);
        console.log('🔥 중복 제거 후 JSON 길이:', jsonData.length);
    }

    // JSON 추출 및 정제
    let cleanJsonData = jsonData.trim();

    // 🔥 JSON 내부에 섞인 마커 제거 (문자열 안에 포함된 경우)
    if (cleanJsonData.includes('###FINAL_RESPONSE###')) {
        console.warn('JSON 내부에 마커 발견 - 제거 중');
        cleanJsonData = cleanJsonData.replace(/###FINAL_RESPONSE###[^"]*"/, '"');
        console.log('🔥 JSON 내부 마커 제거 완료');
    }

    // 마크다운 코드 블록 제거
    if (cleanJsonData.startsWith('```json')) {
        cleanJsonData = cleanJsonData.replace(/^```json\s*/, '');
        cleanJsonData = cleanJsonData.replace(/```\s*$/, '');
        cleanJsonData = cleanJsonData.trim();
        console.log('🔥 마크다운 코드 블록 제거 완료');
    } else if (cleanJsonData.startsWith('```')) {
        cleanJsonData = cleanJsonData.replace(/^```\s*/, '');
        cleanJsonData = cleanJsonData.replace(/```\s*$/, '');
        cleanJsonData = cleanJsonData.trim();
        console.log('🔥 일반 코드 블록 제거 완료');
    }

    // 첫 번째 { 부터 마지막 } 까지 추출
    const firstBrace = cleanJsonData.indexOf('{');
    let lastBrace = cleanJsonData.lastIndexOf('}');

    // 🔥 JSON이 불완전한 경우 자동 완성 (ai-studio.js 방식)
    let openBrackets = (cleanJsonData.match(/\[/g) || []).length;
    let closeBrackets = (cleanJsonData.match(/\]/g) || []).length;
    let openBraces = (cleanJsonData.match(/{/g) || []).length;
    let closeBraces = (cleanJsonData.match(/}/g) || []).length;
    while (closeBrackets < openBrackets) {
        cleanJsonData += ']';
        closeBrackets++;
    }
    while (closeBraces < openBraces) {
        cleanJsonData += '}';
        closeBraces++;
    }

    console.log('첫 번째 { 위치:', firstBrace);
    console.log('마지막 } 위치:', lastBrace);

    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
        cleanJsonData = cleanJsonData.substring(firstBrace, lastBrace + 1);
        console.log('🔥 JSON 추출 성공:', cleanJsonData.length, 'bytes');

        try {
            const parsedResult = JSON.parse(cleanJsonData);
            console.log('JSON 파싱 성공:', parsedResult);

            // 🔥 AI 응답 처리 (studio.html과 동일한 방식)
            processAIResponse(parsedResult, buildAnalysisRequest().query);
            showSuccess('AI 분석이 성공적으로 완료되었습니다!');

            // 1.5초 후 모달 닫기
            setTimeout(() => {
                hideStreamingProgressModal();
            }, 1500);

        } catch (error) {
            console.error('JSON 파싱 실패:', error);
            console.log('파싱 실패한 JSON:', cleanJsonData);

            // 기본 응답 생성
            const basicResponse = {
                analysisId: "access-governance-001",
                query: buildAnalysisRequest().query || "권한 거버넌스 분석",
                naturalLanguageAnswer: cleanJsonData.match(/"naturalLanguageAnswer"\s*:\s*"([^"]+)"/)?.[1] ||
                    "권한 거버넌스 분석이 완료되었습니다.",
                status: "PARTIAL"
            };

            console.log('🔥 기본 응답 생성:', basicResponse);
            processAIResponse(basicResponse, buildAnalysisRequest().query);
            showSuccess('AI 분석이 완료되었습니다 (일부 데이터 누락)');

            setTimeout(() => {
                hideStreamingProgressModal();
            }, 1500);
        }
    } else {
        console.error('🔥 JSON 중괄호를 찾을 수 없음');
        handleJsonParseError(jsonData);
    }
}

/**
 * 🔥 studio.html과 동일한 AI 응답 처리
 */
async function processAIResponse(response, originalQuery) {
    console.log('🧠 AI-Native Response:', response);

    // 🧠 AI 분석 결과 전처리
    const analysisResult = preprocessAIAnalysis(response);

    // 🔥 Inspector에 AI-Native 분석 결과 표시 (모든 섹션 포함)
    displayAINativeAnalysisInInspector(analysisResult, originalQuery);

    // 🔥 시각화 우선순위: 서버 visualizationData 우선 사용!
    if (analysisResult.visualizationData && (analysisResult.visualizationData.nodes || analysisResult.visualizationData.edges)) {
        console.log('🎯 서버 visualizationData 우선 사용 (완전한 구조)');
        await renderIntelligentVisualization(analysisResult.visualizationData, analysisResult);
    } else if (analysisResult.analysisResults && analysisResult.analysisResults.length > 0) {
        console.log('🎯 서버 visualizationData가 없어서 analysisResults 기반 생성');

        // 🔥 analysisResults에서 완전한 USER-GROUP-ROLE-PERMISSION 구조 생성
        const completeVisualizationData = generateCompleteVisualizationFromAnalysis(analysisResult.analysisResults, originalQuery);

        await renderIntelligentVisualization(completeVisualizationData, analysisResult);
    } else {
        // 시각화 데이터가 없으면 캔버스 숨기기만 함
        hideCanvasPlaceholder();
        console.log('🎯 시각화 데이터 없음 - 중앙 패널 표시 생략');
    }
}

/**
 * 🔥 Policy Builder처럼 서버가 클라이언트 구조 제공 - 단순 매핑
 */
function preprocessAIAnalysis(response) {
    console.log('🔥 [SERVER-RESPONSE] 서버가 클라이언트 구조로 응답:', response);

    // 서버 응답 데이터 구조 확인
    console.log('[DATA-STRUCTURE] 서버 응답 데이터 구조:', {
        hasAnalysisResults: !!(response.analysisResults && response.analysisResults.length),
        hasQueryResults: !!(response.queryResults && response.queryResults.length),
        hasRecommendations: !!(response.recommendations && response.recommendations.length),
        hasVisualizationData: !!(response.visualizationData && response.visualizationData.nodes),
        dynamicStatsWillGenerate: true
    });

    // 🔥 서버 응답 데이터를 올바르게 매핑
    const analysisResult = {
        // 서버에서 클라이언트 구조로 제공하는 필드들
        analysisId: response.analysisId || 'unknown',
        query: response.query || '',
        naturalAnswer: response.naturalLanguageAnswer || '',
        confidenceScore: response.confidenceScore || 0,

        // 🔥 권한 거버넌스 전용 필드들 - 서버 데이터 직접 매핑
        overallGovernanceScore: response.overallGovernanceScore || 0,
        riskLevel: response.riskLevel || 'UNKNOWN',
        summary: response.summary || '',
        findings: response.findings || [],
        recommendations: response.recommendations || [],
        actionItems: response.actionItems || [],
        visualizationData: response.visualizationData || null,
        statistics: response.statistics || {},

        // 🔥 서버 데이터 올바른 매핑
        analysisResults: convertServerDataToAnalysisResults(response),
        queryResults: response.queryResults || [],

        // 메타데이터
        processingTime: response.processingTimeMs || 0,

        // 클라이언트 전용 필드 계산
        analysisType: detectAnalysisTypeFromServerData(response),
        complexityScore: 0,
        riskScore: 0,

        // 🔥 올바른 데이터 매핑
        insights: typeof response.insights === 'string' ? [response.insights] : (response.insights || []),
        suggestions: transformRecommendationsToSuggestions(response.recommendations || []),
        anomalies: []
    };

    console.log('🔥 [PREPROCESSED] 클라이언트 구조 기반 분석 결과:', analysisResult);
    return analysisResult;
}

/**
 * 🔥 권한 거버넌스 전용 분석 결과 화면 표시
 */
function displayAINativeAnalysisInInspector(analysisResult, originalQuery) {
    // 🔥 안전한 inspector-panel 요소 가져오기
    const inspectorPanel = document.getElementById('inspector-panel');
    if (!inspectorPanel) {
        console.error('Inspector 패널(inspector-panel)을 찾을 수 없습니다.');
        return;
    }

    // 기존 내용을 모두 지우고 새로운 내용으로 교체
    inspectorPanel.innerHTML = '';

    // 🔥 권한 거버넌스 전용 분석 결과 렌더링
    const html = `
        <!-- 🎯 권한 거버넌스 분석 결과 헤더 -->
        <div class="governance-header">
            <div class="header-title">
                <i class="fas fa-shield-alt text-blue-400 mr-2"></i>
                <h3 class="text-lg font-bold text-slate-200">권한 거버넌스 분석 결과</h3>
            </div>
            <div class="header-timestamp text-xs text-slate-400">
                ${new Date().toLocaleString('ko-KR')}
            </div>
        </div>

        <!-- 📊 거버넌스 점수 및 위험도 섹션 -->
        ${renderGovernanceScoreSection(analysisResult)}

        <!-- 발견 사항 섹션 -->
        ${renderFindingsSection(analysisResult)}

        <!-- 💡 권장사항 섹션 -->
        ${renderRecommendationsSection(analysisResult)}

        <!-- 액션 아이템 섹션 -->
        ${renderActionItemsSection(analysisResult)}

        <!-- 📈 통계 섹션 -->
        ${renderStatisticsSection(analysisResult)}

        <!-- 📋 상세 리포트 버튼 -->
        <div class="detailed-report-section">
            <button class="detailed-report-btn" onclick="showDetailedGovernanceReport(${JSON.stringify(analysisResult).replace(/"/g, '&quot;')})">
                <i class="fas fa-file-alt mr-2"></i>
                상세 분석 리포트 보기
            </button>
        </div>
    `;

    inspectorPanel.innerHTML = html;

    // 🎯 권한 거버넌스 전용 인터랙티브 기능 활성화
    enableGovernanceInteractions(analysisResult);
}

/**
 * 📊 거버넌스 점수 및 위험도 섹션 렌더링
 */
function renderGovernanceScoreSection(analysisResult) {
    const governanceScore = analysisResult.overallGovernanceScore || 0;
    const riskLevel = analysisResult.riskLevel || 'UNKNOWN';
    const summary = analysisResult.summary || '분석 결과가 없습니다.';
    
    const scoreClass = governanceScore >= 80 ? 'text-green-400' : 
                      governanceScore >= 60 ? 'text-yellow-400' : 'text-red-400';
    
    const riskClass = riskLevel === 'LOW' ? 'text-green-400' :
                     riskLevel === 'MEDIUM' ? 'text-yellow-400' :
                     riskLevel === 'HIGH' ? 'text-orange-400' : 'text-red-400';
    
    const riskIcon = riskLevel === 'LOW' ? 'fa-check-circle' :
                    riskLevel === 'MEDIUM' ? 'fa-exclamation-triangle' :
                    riskLevel === 'HIGH' ? 'fa-exclamation-circle' : 'fa-times-circle';
    
    return `
        <div class="governance-score-section bg-slate-800/50 rounded-lg p-4 mb-4 border border-slate-600">
            <div class="score-header flex items-center justify-between mb-3">
                <h4 class="text-slate-200 font-semibold">
                    <i class="fas fa-chart-line text-blue-400 mr-2"></i>
                    거버넌스 점수
                </h4>
                <div class="score-badge ${scoreClass} font-bold text-xl">
                    ${governanceScore.toFixed(1)}/100
                </div>
            </div>
            
            <div class="risk-level flex items-center justify-between mb-3">
                <span class="text-slate-300 text-sm">위험도:</span>
                <span class="risk-badge ${riskClass} font-semibold">
                    <i class="fas ${riskIcon} mr-1"></i>
                    ${getRiskLevelText(riskLevel)}
                </span>
            </div>
            
            <div class="summary-text text-slate-300 text-sm leading-relaxed">
                ${summary}
            </div>
        </div>
    `;
}

/**
 * 발견 사항 섹션 렌더링
 */
function renderFindingsSection(analysisResult) {
    const findings = analysisResult.findings || [];
    
    if (findings.length === 0) {
        return `
            <div class="findings-section bg-green-900/30 rounded-lg p-4 mb-4 border border-green-500/30">
                <div class="findings-header flex items-center mb-3">
                    <i class="fas fa-search text-green-400 mr-2"></i>
                    <h4 class="text-slate-200 font-semibold">발견 사항</h4>
                    <span class="ml-auto text-green-300 text-sm">0건</span>
                </div>
                <p class="text-green-300 text-sm">발견된 이상 징후가 없습니다.</p>
            </div>
        `;
    }
    
    const findingsHtml = findings.map(finding => {
        const severityClass = finding.severity === 'HIGH' ? 'text-red-400' :
                            finding.severity === 'MEDIUM' ? 'text-yellow-400' : 'text-blue-400';
        
        return `
            <div class="finding-item bg-slate-800/50 rounded-lg p-3 mb-2 border-l-4 border-slate-600">
                <div class="finding-header flex items-center justify-between mb-2">
                    <h5 class="text-slate-200 font-medium">${finding.type || '이상 징후'}</h5>
                    <span class="severity-badge ${severityClass} text-xs px-2 py-1 rounded bg-slate-700">
                        ${getSeverityText(finding.severity)}
                    </span>
                </div>
                <p class="finding-description text-slate-300 text-sm mb-2">
                    ${finding.description || '설명 없음'}
                </p>
                <div class="finding-details text-xs text-slate-400">
                    <span class="mr-3">영향 사용자: ${(finding.affectedUsers || []).join(', ') || 'N/A'}</span>
                    <span>영향 역할: ${(finding.affectedRoles || []).join(', ') || 'N/A'}</span>
                </div>
            </div>
        `;
    }).join('');
    
    return `
        <div class="findings-section bg-slate-800/50 rounded-lg p-4 mb-4 border border-slate-600">
            <div class="findings-header flex items-center mb-3">
                <i class="fas fa-search text-blue-400 mr-2"></i>
                <h4 class="text-slate-200 font-semibold">발견 사항</h4>
                <span class="ml-auto text-slate-300 text-sm">${findings.length}건</span>
            </div>
            <div class="findings-content">
                ${findingsHtml}
            </div>
        </div>
    `;
}

/**
 * 💡 권장사항 섹션 렌더링
 */
function renderRecommendationsSection(analysisResult) {
    const recommendations = analysisResult.recommendations || [];
    
    if (recommendations.length === 0) {
        return `
            <div class="recommendations-section bg-blue-900/30 rounded-lg p-4 mb-4 border border-blue-500/30">
                <div class="recommendations-header flex items-center mb-3">
                    <i class="fas fa-lightbulb text-blue-400 mr-2"></i>
                    <h4 class="text-slate-200 font-semibold">권장사항</h4>
                    <span class="ml-auto text-blue-300 text-sm">0건</span>
                </div>
                <p class="text-blue-300 text-sm">권장사항이 없습니다.</p>
            </div>
        `;
    }
    
    const recommendationsHtml = recommendations.map(rec => {
        const priorityClass = rec.priority === 'HIGH' ? 'text-red-400' :
                            rec.priority === 'MEDIUM' ? 'text-yellow-400' : 'text-blue-400';
        
        return `
            <div class="recommendation-item bg-slate-800/50 rounded-lg p-3 mb-2 border-l-4 border-blue-500">
                <div class="recommendation-header flex items-center justify-between mb-2">
                    <h5 class="text-slate-200 font-medium">${rec.title || rec.category || '권장사항'}</h5>
                    <span class="priority-badge ${priorityClass} text-xs px-2 py-1 rounded bg-slate-700">
                        ${getPriorityText(rec.priority)}
                    </span>
                </div>
                <p class="recommendation-description text-slate-300 text-sm mb-2">
                    ${rec.description || '설명 없음'}
                </p>
                ${rec.implementationSteps && rec.implementationSteps.length > 0 ? `
                    <div class="implementation-steps text-xs text-slate-400">
                        <strong>구현 단계:</strong>
                        <ol class="list-decimal list-inside mt-1">
                            ${rec.implementationSteps.map(step => `<li>${step}</li>`).join('')}
                        </ol>
                    </div>
                ` : ''}
            </div>
        `;
    }).join('');
    
    return `
        <div class="recommendations-section bg-slate-800/50 rounded-lg p-4 mb-4 border border-slate-600">
            <div class="recommendations-header flex items-center mb-3">
                <i class="fas fa-lightbulb text-yellow-400 mr-2"></i>
                <h4 class="text-slate-200 font-semibold">권장사항</h4>
                <span class="ml-auto text-slate-300 text-sm">${recommendations.length}건</span>
            </div>
            <div class="recommendations-content">
                ${recommendationsHtml}
            </div>
        </div>
    `;
}

/**
 * 액션 아이템 섹션 렌더링
 */
function renderActionItemsSection(analysisResult) {
    const actionItems = analysisResult.actionItems || [];
    
    if (actionItems.length === 0) {
        return `
            <div class="action-items-section bg-yellow-900/30 rounded-lg p-4 mb-4 border border-yellow-500/30">
                <div class="action-items-header flex items-center mb-3">
                    <i class="fas fa-tasks text-yellow-400 mr-2"></i>
                    <h4 class="text-slate-200 font-semibold">액션 아이템</h4>
                    <span class="ml-auto text-yellow-300 text-sm">0건</span>
                </div>
                <p class="text-yellow-300 text-sm">액션 아이템이 없습니다.</p>
            </div>
        `;
    }
    
    const actionItemsHtml = actionItems.map(item => {
        const statusClass = item.status === 'COMPLETED' ? 'text-green-400' :
                          item.status === 'IN_PROGRESS' ? 'text-blue-400' : 'text-yellow-400';
        
        return `
            <div class="action-item bg-slate-800/50 rounded-lg p-3 mb-2 border-l-4 border-yellow-500">
                <div class="action-header flex items-center justify-between mb-2">
                    <h5 class="text-slate-200 font-medium">${item.title || '액션 아이템'}</h5>
                    <span class="status-badge ${statusClass} text-xs px-2 py-1 rounded bg-slate-700">
                        ${getStatusText(item.status)}
                    </span>
                </div>
                <p class="action-description text-slate-300 text-sm mb-2">
                    ${item.description || '설명 없음'}
                </p>
                <div class="action-details text-xs text-slate-400">
                    <span class="mr-3">담당자: ${item.assignee || 'N/A'}</span>
                    <span>기한: ${item.dueDate || 'N/A'}</span>
                </div>
            </div>
        `;
    }).join('');
    
    return `
        <div class="action-items-section bg-slate-800/50 rounded-lg p-4 mb-4 border border-slate-600">
            <div class="action-items-header flex items-center mb-3">
                <i class="fas fa-tasks text-green-400 mr-2"></i>
                <h4 class="text-slate-200 font-semibold">액션 아이템</h4>
                <span class="ml-auto text-slate-300 text-sm">${actionItems.length}건</span>
            </div>
            <div class="action-items-content">
                ${actionItemsHtml}
            </div>
        </div>
    `;
}

/**
 * 📈 통계 섹션 렌더링
 */
function renderStatisticsSection(analysisResult) {
    const statistics = analysisResult.statistics || {};
    
    if (Object.keys(statistics).length === 0) {
        return `
            <div class="statistics-section bg-slate-800/50 rounded-lg p-4 mb-4 border border-slate-600">
                <div class="statistics-header flex items-center mb-3">
                    <i class="fas fa-chart-bar text-purple-400 mr-2"></i>
                    <h4 class="text-slate-200 font-semibold">통계</h4>
                </div>
                <p class="text-slate-400 text-sm">통계 데이터가 없습니다.</p>
            </div>
        `;
    }
    
    const statsHtml = Object.entries(statistics).map(([key, value]) => {
        const displayKey = getStatisticsDisplayName(key);
        const displayValue = typeof value === 'number' ? value.toLocaleString() : value;
        
        return `
            <div class="stat-item flex justify-between items-center py-2 border-b border-slate-700 last:border-b-0">
                <span class="stat-label text-slate-300 text-sm">${displayKey}</span>
                <span class="stat-value text-slate-200 font-semibold">${displayValue}</span>
            </div>
        `;
    }).join('');
    
    return `
        <div class="statistics-section bg-slate-800/50 rounded-lg p-4 mb-4 border border-slate-600">
            <div class="statistics-header flex items-center mb-3">
                <i class="fas fa-chart-bar text-purple-400 mr-2"></i>
                <h4 class="text-slate-200 font-semibold">통계</h4>
                <span class="ml-auto text-slate-300 text-sm">${Object.keys(statistics).length}개</span>
            </div>
            <div class="statistics-content">
                ${statsHtml}
            </div>
        </div>
    `;
}

/**
 * 분석 요청 검증
 */
function validateAnalysisRequest() {
    if (!selectedAnalysisType) {
        showError('분석 유형을 선택해주세요');
        return false;
    }
    
    const auditScope = document.getElementById('auditScope').value;
    if (!auditScope) {
        showError('감사 범위를 선택해주세요');
        return false;
    }
    
    return true;
}

/**
 * 분석 요청 데이터 구성
 */
function buildAnalysisRequest() {
    const form = document.getElementById('analysisForm');
    const formData = new FormData(form);
    
    // 선택된 사용자/그룹 정보를 쿼리로 구성
    const selectedUserNames = [];
    const selectedGroupNames = [];
    
    selectedItems.forEach(key => {
        const [type, id] = key.split('_');
        if (type === 'USER') {
            const user = allUsersAndGroups.users.find(u => u.id == id);
            if (user) selectedUserNames.push(user.name);
        } else if (type === 'GROUP') {
            const group = allUsersAndGroups.groups.find(g => g.id == id);
            if (group) selectedGroupNames.push(group.name);
        }
    });
    
    // 쿼리 구성
    let query = '';
    if (selectedUserNames.length > 0 || selectedGroupNames.length > 0) {
        if (selectedUserNames.length > 0) {
            query += `사용자: ${selectedUserNames.join(', ')}`;
        }
        if (selectedGroupNames.length > 0) {
            if (query) query += ' | ';
            query += `그룹: ${selectedGroupNames.join(', ')}`;
        }
        query += '에 대한 ';
    }
    
    // 분석 유형에 따른 쿼리 추가
    const analysisTypeNames = {
        'COMPREHENSIVE': '종합 권한 거버넌스 분석',
        'EXCESSIVE_PERMISSIONS': '과도한 권한 탐지',
        'DORMANT_PERMISSIONS': '미사용 권한 분석',
        'SOD_VIOLATIONS': '업무 분리 위반 검사'
    };
    query += analysisTypeNames[selectedAnalysisType] || '권한 거버넌스 분석';
    
    const requestData = {
        analysisType: selectedAnalysisType,
        auditScope: formData.get('auditScope'),
        priority: formData.get('priority'),
        query: query,
        enableDormantPermissionAnalysis: document.getElementById('enableDormantPermissionAnalysis').checked,
        enableExcessivePermissionDetection: document.getElementById('enableExcessivePermissionDetection').checked,
        enableSodViolationCheck: document.getElementById('enableSodViolationCheck').checked
    };
    
    console.log('📤 분석 요청 데이터:', requestData);
    return requestData;
}

/**
 * 분석 결과 표시
 */
function displayAnalysisResult(result) {
    console.log('📊 분석 결과 표시:', result);
    
    // 거버넌스 점수
    const governanceScore = document.getElementById('governanceScore');
    governanceScore.textContent = result.overallGovernanceScore ? result.overallGovernanceScore.toFixed(1) + '%' : 'N/A';
    
    // 위험도
    const riskLevel = document.getElementById('riskLevel');
    riskLevel.textContent = result.riskLevel || 'N/A';
    
    // 발견 사항
    displayFindings(result.findings);
    
    // 권장사항
    displayRecommendations(result.recommendations);
    
    // 액션 아이템
    displayActionItems(result.actionItems);
    
    // 결과 표시
    showResults();
}

/**
 * 발견 사항 표시
 */
function displayFindings(findings) {
    const container = document.getElementById('findingsList');
    container.innerHTML = '';
    
    if (!findings || findings.length === 0) {
        container.innerHTML = '<div class="bg-green-900/30 border border-green-500/30 rounded-lg p-3 text-green-300">발견된 이상 징후가 없습니다.</div>';
        return;
    }
    
    findings.forEach(finding => {
        const item = document.createElement('div');
        item.className = 'bg-slate-800/50 border border-slate-600 rounded-lg p-3 mb-2';
        item.innerHTML = `
            <div class="flex justify-between items-start mb-2">
                <h6 class="text-slate-200 font-semibold">${finding.anomalyType || '이상 징후'}</h6>
                <span class="text-xs px-2 py-1 rounded bg-yellow-600/30 text-yellow-300">${finding.severity || 'N/A'}</span>
            </div>
            <p class="text-slate-300 text-sm mb-2">${finding.description || '설명 없음'}</p>
            <div class="text-xs text-slate-400">
                사용자: ${finding.userName || finding.userId || 'N/A'} | 
                권한: ${finding.permissionName || 'N/A'} | 
                역할: ${finding.roleName || 'N/A'}
            </div>
        `;
        container.appendChild(item);
    });
}

/**
 * 권장사항 표시
 */
function displayRecommendations(recommendations) {
    const container = document.getElementById('recommendationsList');
    container.innerHTML = '';
    
    if (!recommendations || recommendations.length === 0) {
        container.innerHTML = '<div class="bg-blue-900/30 border border-blue-500/30 rounded-lg p-3 text-blue-300">권장사항이 없습니다.</div>';
        return;
    }
    
    recommendations.forEach(recommendation => {
        const item = document.createElement('div');
        item.className = 'bg-slate-800/50 border border-slate-600 rounded-lg p-3 mb-2';
        item.innerHTML = `
            <div class="flex items-start gap-2">
                <i class="fas fa-lightbulb text-yellow-500 mt-1"></i>
                <p class="text-slate-300 text-sm">${recommendation}</p>
            </div>
        `;
        container.appendChild(item);
    });
}

/**
 * 액션 아이템 표시
 */
function displayActionItems(actionItems) {
    const container = document.getElementById('actionItemsList');
    container.innerHTML = '';
    
    if (!actionItems || actionItems.length === 0) {
        container.innerHTML = '<div class="bg-yellow-900/30 border border-yellow-500/30 rounded-lg p-3 text-yellow-300">액션 아이템이 없습니다.</div>';
        return;
    }
    
    actionItems.forEach(actionItem => {
        const item = document.createElement('div');
        item.className = 'bg-slate-800/50 border border-slate-600 rounded-lg p-3 mb-2';
        item.innerHTML = `
            <div class="flex items-start gap-2">
                <i class="fas fa-tasks text-blue-500 mt-1"></i>
                <p class="text-slate-300 text-sm">${actionItem}</p>
            </div>
        `;
        container.appendChild(item);
    });
}

/**
 * 스트리밍 내용 추가
 */
function appendStreamingContent(content) {
    const container = document.getElementById('streamingContent');
    const timestamp = new Date().toLocaleTimeString();
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'mb-2';
    contentDiv.innerHTML = `
        <small class="text-slate-400">[${timestamp}]</small>
        <span class="text-slate-300">${content}</span>
    `;
    
    container.appendChild(contentDiv);
    container.scrollTop = container.scrollHeight;
}

/**
 * 로딩 표시
 */
function showLoading() {
    document.getElementById('loadingIndicator').classList.remove('hidden');
    document.getElementById('initial-state').classList.add('hidden');
}

/**
 * 로딩 숨김
 */
function hideLoading() {
    document.getElementById('loadingIndicator').classList.add('hidden');
}

/**
 * 결과 표시
 */
function showResults() {
    document.getElementById('analysisResult').classList.remove('hidden');
    document.getElementById('initial-state').classList.add('hidden');
}

/**
 * 결과 숨김
 */
function hideResults() {
    document.getElementById('analysisResult').classList.add('hidden');
}

/**
 * 스트리밍 결과 표시
 */
function showStreamingResult() {
    document.getElementById('streamingResult').classList.remove('hidden');
    document.getElementById('streamingContent').innerHTML = '';
    document.getElementById('initial-state').classList.add('hidden');
}

/**
 * 스트리밍 결과 숨김
 */
function hideStreamingResult() {
    document.getElementById('streamingResult').classList.add('hidden');
}

/**
 * 🎥 스트리밍 진행 모달 표시 (ai-studio.js와 동일한 방식)
 */
function showStreamingProgressModal(query) {
    // 기존 모달이 있으면 제거
    hideStreamingProgressModal();

    // ai-studio.js와 동일한 방식으로 동적 HTML 생성
    const modalHtml = `
        <div id="streaming-modal" class="streaming-modal" style="display: flex; opacity: 1;">
            <div class="streaming-modal-content">
                <div class="streaming-header">
                    <h3><i class="fas fa-brain mr-2"></i>AI 권한 거버넌스 분석 진행 중</h3>
                    <div class="streaming-query">
                        <strong>질의:</strong> <span id="streaming-query-text">${escapeHtml(query)}</span>
                    </div>
                </div>
                
                <div class="streaming-progress">
                    <div class="streaming-content" id="streaming-content" data-initial="true">
                        <div class="streaming-step" style="opacity: 1; transform: translateY(0);">
                            <i class="fas fa-cog fa-spin mr-2"></i>AI가 권한 거버넌스 분석을 시작합니다...
                        </div>
                    </div>
                </div>
                
                <div class="streaming-footer">
                    <div class="streaming-animation">
                        <div class="dot"></div>
                        <div class="dot"></div>
                        <div class="dot"></div>
                    </div>
                    <small>AI가 권한 거버넌스 구조를 분석하고 있습니다. 잠시만 기다려주세요.</small>
                </div>
            </div>
        </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    // 모달 강제 표시
    const modal = document.getElementById('streaming-modal');
    if (modal) {
        modal.classList.add('show');
        modal.style.display = 'flex';
        modal.style.opacity = '1';
        console.log('스트리밍 모달 표시됨');
    }
}

/**
 * 🎥 스트리밍 진행 모달 숨김 (ai-studio.js와 동일한 방식)
 */
function hideStreamingProgressModal() {
    console.log('hideStreamingProgressModal 호출됨 - 스트리밍 완료 처리');

    const modal = document.getElementById('streaming-modal');
    if (modal) {
        console.log('모달 발견 - 실제로 숨기기 진행');

        // 모달을 완전히 숨기기
        modal.classList.remove('show');
        modal.style.display = 'none';
        console.log('🎥 스트리밍 모달 숨김');

        // 모달을 DOM에서 완전히 제거
        setTimeout(() => {
            if (modal.parentNode) {
                modal.parentNode.removeChild(modal);
                console.log('🎥 스트리밍 모달 DOM에서 제거 완료');
            }
        }, 1000);
    } else {
        console.error('모달을 찾을 수 없음!');
    }
}

/**
 * 🌊 스트리밍 단계 추가 (studio.html과 동일한 방식)
 */
function addStreamingStep(text) {
    const streamingContent = document.getElementById('streaming-content');
    if (!streamingContent) {
        console.warn('스트리밍 컨텐츠 요소를 찾을 수 없습니다.');
        return;
    }

    const step = document.createElement('div');
    step.className = 'streaming-step';
    step.style.opacity = '0';
    step.style.transform = 'translateY(20px)';
    step.style.transition = 'all 0.3s ease';
    
    step.innerHTML = `
        <i class="fas fa-arrow-right mr-2 text-indigo-400"></i>
        ${escapeHtml(text)}
    `;
    
    streamingContent.appendChild(step);
    
    // 애니메이션 적용
    setTimeout(() => {
        step.style.opacity = '1';
        step.style.transform = 'translateY(0)';
    }, 50);
    
    // 스크롤을 맨 아래로
    streamingContent.scrollTop = streamingContent.scrollHeight;
}

/**
 * HTML 이스케이프 (studio.html과 동일한 방식)
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * 오류 메시지 표시 (팝업창)
 */
function showError(message) {
    // 팝업창 생성
    const popup = document.createElement('div');
    popup.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
    popup.innerHTML = `
        <div class="bg-slate-800 border border-red-500 rounded-lg p-6 max-w-md mx-4">
            <div class="flex items-center gap-3 mb-4">
                <i class="fas fa-exclamation-triangle text-red-400 text-xl"></i>
                <h3 class="text-red-300 font-bold text-lg">오류</h3>
            </div>
            <p class="text-slate-300 mb-4">${message}</p>
            <div class="flex justify-end">
                <button onclick="this.closest('.fixed').remove()" class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors">
                    확인
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(popup);
    
    // ESC 키로 닫기
    const handleEsc = (e) => {
        if (e.key === 'Escape') {
            popup.remove();
            document.removeEventListener('keydown', handleEsc);
        }
    };
    document.addEventListener('keydown', handleEsc);
    
    // 배경 클릭으로 닫기
    popup.addEventListener('click', (e) => {
        if (e.target === popup) {
            popup.remove();
            document.removeEventListener('keydown', handleEsc);
        }
    });
}

/**
 * 성공 메시지 표시
 */
function showSuccess(message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'bg-green-900/30 border border-green-500/30 rounded-lg p-4 mb-4 text-green-300';
    alertDiv.innerHTML = `
        <div class="flex items-center gap-2">
            <i class="fas fa-check-circle"></i>
            <strong>성공!</strong> ${message}
        </div>
    `;
    
    const main = document.querySelector('main');
    main.insertBefore(alertDiv, main.firstChild);
    
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 3000);
}

// 페이지 언로드 시 스트리밍 연결 종료
window.addEventListener('beforeunload', function() {
    if (currentEventSource) {
        currentEventSource.close();
    }
}); 

/**
 * JSON 파싱 에러 처리 메서드
 */
function handleJsonParseError(jsonData) {
    addStreamingStep('결과 데이터 처리 중 오류가 발생했습니다.');

    const errorResponse = {
        analysisId: 'error-001',
        query: buildAnalysisRequest().query,
        naturalLanguageAnswer: 'JSON 파싱 오류로 인해 완전한 분석 결과를 표시할 수 없습니다.',
        status: 'ERROR'
    };

    processAIResponse(errorResponse, buildAnalysisRequest().query);
    showError('분석 결과 처리 중 오류가 발생했습니다');

    setTimeout(() => {
        hideStreamingProgressModal();
    }, 1500);
}

/**
 * 🔥 서버 데이터를 클라이언트 분석 결과로 변환
 */
function convertServerDataToAnalysisResults(response) {
    if (!response.analysisResults || !Array.isArray(response.analysisResults)) {
        return [];
    }

    return response.analysisResults.map(result => ({
        userName: result.userName || result.user || '',
        groupName: result.groupName || result.group || '',
        roleName: result.roleName || result.role || '',
        hasPermission: result.hasPermission || false,
        permissionName: result.permissionName || result.permission || '',
        accessPath: result.accessPath || [],
        confidence: result.confidence || 0.8
    }));
}

/**
 * 📊 실제 서버 데이터 기반 동적 통계 생성
 */
function generateDynamicStatistics(response) {
    const stats = {};

    try {
        // 1. 📊 analysisResults 기반 권한 통계 (실제 서버 구조 대응)
        if (response.analysisResults && Array.isArray(response.analysisResults)) {
            // 실제 서버 구조: {userName, groupName, roleName, hasPermission, permissionName}
            const usersWithPermission = response.analysisResults.filter(result =>
                result.hasPermission === true
            ).length;

            const totalUsers = response.analysisResults.length;
            const permissionRate = totalUsers > 0 ? (usersWithPermission / totalUsers * 100).toFixed(1) : 0;

            stats['permissionAccessRate'] = `${permissionRate}%`;
            stats['usersWithPermission'] = usersWithPermission;
            stats['totalAnalyzedUsers'] = totalUsers;
        }

        // 2. 📊 recommendations 기반 권장사항 통계
        if (response.recommendations && Array.isArray(response.recommendations)) {
            stats['totalRecommendations'] = response.recommendations.length;
            
            const highPriorityRecs = response.recommendations.filter(rec => 
                rec.priority === 'HIGH' || rec.importance === 'HIGH'
            ).length;
            stats['highPriorityRecommendations'] = highPriorityRecs;
        }

        // 3. 📊 governanceScore 기반 거버넌스 점수
        if (response.overallGovernanceScore !== undefined) {
            stats['overallGovernanceScore'] = `${response.overallGovernanceScore.toFixed(1)}/100`;
        }

        // 4. 📊 riskLevel 기반 위험도
        if (response.riskLevel) {
            stats['riskLevel'] = response.riskLevel;
        }

        // 5. 📊 findings 기반 발견사항 통계
        if (response.findings && Array.isArray(response.findings)) {
            stats['totalFindings'] = response.findings.length;
            
            const criticalFindings = response.findings.filter(finding => 
                finding.severity === 'CRITICAL' || finding.riskLevel === 'CRITICAL'
            ).length;
            stats['criticalFindings'] = criticalFindings;
        }

        console.log('📊 동적 통계 생성 완료:', stats);
        return stats;

    } catch (error) {
        console.error('동적 통계 생성 실패:', error);
        return {
            'error': '통계 생성 중 오류 발생',
            'totalAnalyzedUsers': 0
        };
    }
}

/**
 * 🔥 서버 데이터에서 분석 유형 감지
 */
function detectAnalysisTypeFromServerData(response) {
    if (response.analysisType) {
        return response.analysisType;
    }
    
    // 분석 유형 추론
    if (response.query && response.query.includes('과도한')) {
        return 'EXCESSIVE_PERMISSION';
    } else if (response.query && response.query.includes('미사용')) {
        return 'DORMANT_PERMISSION';
    } else if (response.query && response.query.includes('업무 분리')) {
        return 'SOD_VIOLATION';
    } else {
        return 'COMPREHENSIVE';
    }
}

/**
 * 🔥 recommendations를 suggestions 형태로 변환
 */
function transformRecommendationsToSuggestions(recommendations) {
    if (!Array.isArray(recommendations)) {
        return [];
    }

    return recommendations.map(rec => ({
        type: rec.type || 'GENERAL',
        title: rec.title || rec.description || '권장사항',
        description: rec.description || rec.title || '',
        priority: rec.priority || rec.importance || 'MEDIUM',
        impact: rec.impact || 'MEDIUM',
        effort: rec.effort || 'MEDIUM'
    }));
}

/**
 * 신뢰도 클래스 반환
 */
function getConfidenceClass(score) {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    return 'text-red-400';
}

/**
 * 신뢰도 텍스트 반환
 */
function getConfidenceText(score) {
    if (score >= 80) return '신뢰도 높음';
    if (score >= 60) return '신뢰도 보통';
    return '신뢰도 낮음';
}

/**
 * 🔥 AI 자연어 응답 포맷팅
 */
function formatAINativeAnswer(answer, originalQuery, analysisResults = null) {
    if (!answer) {
        return '<p class="text-slate-400">AI 분석 결과가 없습니다.</p>';
    }

    // 기본 응답 포맷팅
    let formattedAnswer = answer
        .replace(/\n/g, '<br>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>');

    // 분석 결과가 있으면 추가 정보 표시
    if (analysisResults && analysisResults.length > 0) {
        const usersWithPermission = analysisResults.filter(result => result.hasPermission).length;
        const totalUsers = analysisResults.length;

        formattedAnswer += `
            <div class="analysis-summary mt-4 p-3 bg-slate-800/50 rounded-lg">
                <div class="summary-header mb-2">
                    <i class="fas fa-chart-pie text-blue-400 mr-2"></i>
                    <strong>분석 요약</strong>
                </div>
                <div class="summary-content text-sm text-slate-300">
                    <div class="summary-item">
                        <span class="summary-label">분석 대상:</span>
                        <span class="summary-value">${totalUsers}명의 사용자/그룹</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">권한 보유:</span>
                        <span class="summary-value">${usersWithPermission}명</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">권한 비율:</span>
                        <span class="summary-value">${totalUsers > 0 ? (usersWithPermission / totalUsers * 100).toFixed(1) : 0}%</span>
                    </div>
                </div>
            </div>
        `;
    }

    return `<div class="ai-answer">${formattedAnswer}</div>`;
}

/**
 * 🎯 인터랙티브 기능 활성화 (스튜디오 스타일 - 사용하지 않음)
 */
function enableAINativeInteractions(analysisResult) {
    // 권한 거버넌스에서는 사용하지 않음
    console.log('스튜디오 스타일 인터랙션은 권한 거버넌스에서 사용하지 않습니다.');
}

/**
 * 🔥 지능형 시각화 렌더링
 */
async function renderIntelligentVisualization(visualizationData, analysisResult) {
    console.log('🎯 지능형 시각화 렌더링 시작:', visualizationData);

    try {
        // Cytoscape.js를 사용한 시각화 (studio.html과 동일)
        await displayCytoscapeDiagram(visualizationData);
        
        // AI 분석 결과와 시각화 데이터 융합
        if (analysisResult) {
            createAIVisualizationOverlay(analysisResult, visualizationData);
        }

        console.log('지능형 시각화 렌더링 완료');

    } catch (error) {
        console.error('지능형 시각화 렌더링 실패:', error);
        showCytoscapeError(document.getElementById('canvas-content'), error);
    }
}

/**
 * 🔥 analysisResults에서 완전한 시각화 데이터 생성
 */
function generateCompleteVisualizationFromAnalysis(analysisResults, originalQuery) {
    console.log('🎯 analysisResults 기반 시각화 데이터 생성:', analysisResults);

    const nodes = [];
    const edges = [];
    const nodeIds = new Set();

    // 사용자 노드 추가
    analysisResults.forEach(result => {
        if (result.userName && !nodeIds.has(`user_${result.userName}`)) {
            nodes.push({
                id: `user_${result.userName}`,
                label: result.userName,
                type: 'USER',
                hasPermission: result.hasPermission,
                confidence: result.confidence || 0.8
            });
            nodeIds.add(`user_${result.userName}`);
        }

        if (result.groupName && !nodeIds.has(`group_${result.groupName}`)) {
            nodes.push({
                id: `group_${result.groupName}`,
                label: result.groupName,
                type: 'GROUP',
                hasPermission: result.hasPermission,
                confidence: result.confidence || 0.8
            });
            nodeIds.add(`group_${result.groupName}`);
        }

        if (result.roleName && !nodeIds.has(`role_${result.roleName}`)) {
            nodes.push({
                id: `role_${result.roleName}`,
                label: result.roleName,
                type: 'ROLE',
                hasPermission: result.hasPermission,
                confidence: result.confidence || 0.8
            });
            nodeIds.add(`role_${result.roleName}`);
        }

        if (result.permissionName && !nodeIds.has(`permission_${result.permissionName}`)) {
            nodes.push({
                id: `permission_${result.permissionName}`,
                label: result.permissionName,
                type: 'PERMISSION',
                hasPermission: result.hasPermission,
                confidence: result.confidence || 0.8
            });
            nodeIds.add(`permission_${result.permissionName}`);
        }
    });

    // 엣지 추가 (사용자-그룹-역할-권한 연결)
    analysisResults.forEach(result => {
        if (result.userName && result.groupName) {
            edges.push({
                source: `user_${result.userName}`,
                target: `group_${result.groupName}`,
                type: 'USER_GROUP',
                hasPermission: result.hasPermission
            });
        }

        if (result.groupName && result.roleName) {
            edges.push({
                source: `group_${result.groupName}`,
                target: `role_${result.roleName}`,
                type: 'GROUP_ROLE',
                hasPermission: result.hasPermission
            });
        }

        if (result.roleName && result.permissionName) {
            edges.push({
                source: `role_${result.roleName}`,
                target: `permission_${result.permissionName}`,
                type: 'ROLE_PERMISSION',
                hasPermission: result.hasPermission
            });
        }
    });

    return { nodes, edges };
}

/**
 * 캔버스 플레이스홀더 숨기기
 */
function hideCanvasPlaceholder() {
    const placeholder = document.getElementById('canvas-placeholder');
    if (placeholder) {
        placeholder.classList.add('hidden');
    }
}

/**
 * 🔥 Cytoscape.js 다이어그램 표시
 */
async function displayCytoscapeDiagram(visualizationData) {
    console.log('🎯 Cytoscape.js 다이어그램 렌더링 시작');
    console.log('📊 시각화 데이터:', visualizationData);

    try {
        // 🔥 안전한 컨테이너 요소 가져오기
        const container = document.getElementById('canvas-content');
        if (!container) {
            console.error('Cytoscape 컨테이너(canvas-content)를 찾을 수 없습니다.');
            return;
        }

        // 🔥 누락된 노드 자동 생성 (Cytoscape.js 오류 방지)
        const existingNodeIds = new Set(visualizationData.nodes.map(node => node.id));
        const missingNodes = [];
        
        visualizationData.edges.forEach(edge => {
            if (!existingNodeIds.has(edge.source)) {
                console.log('누락된 소스 노드 발견:', edge.source);
                missingNodes.push({
                    id: edge.source,
                    type: 'MISSING',
                    label: edge.source,
                    permissions: 0,
                    riskLevel: 'UNKNOWN'
                });
                existingNodeIds.add(edge.source);
            }
            if (!existingNodeIds.has(edge.target)) {
                console.log('누락된 타겟 노드 발견:', edge.target);
                missingNodes.push({
                    id: edge.target,
                    type: 'MISSING', 
                    label: edge.target,
                    permissions: 0,
                    riskLevel: 'UNKNOWN'
                });
                existingNodeIds.add(edge.target);
            }
        });
        
        // 누락된 노드들을 기존 노드 배열에 추가
        if (missingNodes.length > 0) {
            console.log('🔧 누락된 노드 자동 생성:', missingNodes);
            visualizationData.nodes = [...visualizationData.nodes, ...missingNodes];
        }

        // 기존 Cytoscape 인스턴스 제거
        if (cytoscapeInstance) {
            cytoscapeInstance.destroy();
        }

        // Cytoscape 데이터 변환
        const elements = convertToCytoscapeFormat(visualizationData);

        // Cytoscape 인스턴스 생성
        cytoscapeInstance = cytoscape({
            container: container,
            elements: elements,
            style: getCytoscapeStyles(),
            layout: getHierarchicalLayout(),
            wheelSensitivity: 0.5
        });

        // 이벤트 설정
        setupCytoscapeEvents(cytoscapeInstance);

        console.log('Cytoscape.js 다이어그램 표시 완료');

    } catch (error) {
        console.error('Cytoscape.js 다이어그램 표시 실패:', error);
        // 에러 처리 시에도 안전하게 컨테이너 확인
        const container = document.getElementById('canvas-content');
        if (container) {
            showCytoscapeError(container, error);
        }
    }
}

/**
 * 🔥 Cytoscape 형식으로 데이터 변환
 */
function convertToCytoscapeFormat(visualizationData) {
    const elements = [];

    // 노드 추가
    if (visualizationData.nodes) {
        visualizationData.nodes.forEach(node => {
            elements.push({
                data: {
                    id: node.id,
                    label: node.label,
                    type: node.type,
                    hasPermission: node.hasPermission,
                    confidence: node.confidence
                }
            });
        });
    }

            // 엣지 추가
        if (visualizationData.edges) {
            visualizationData.edges.forEach(edge => {
                elements.push({
                    data: {
                        id: `${edge.source}_${edge.target}`,
                        source: edge.source,
                        target: edge.target,
                        type: edge.type,
                        hasPermission: edge.hasPermission,
                        reviewNeeded: edge.reviewNeeded || false
                    }
                });
            });
        }

    return elements;
}

/**
 * 🔥 Cytoscape 스타일 정의
 */
function getCytoscapeStyles() {
    return [
        // 기본 노드 스타일
        {
            selector: 'node',
            style: {
                'background-color': '#3b82f6',
                'label': 'data(label)',
                'color': '#ffffff',
                'font-size': '14px',
                'font-weight': 'bold',
                'text-wrap': 'wrap',
                'text-max-width': '100px',
                'border-width': 3,
                'border-color': '#1e40af',
                'width': 70,
                'height': 70,
                'text-valign': 'center',
                'text-halign': 'center'
            }
        },
        // 사용자 노드
        {
            selector: 'node[type = "USER"]',
            style: {
                'background-color': '#38bdf8',
                'border-color': '#0ea5e9',
                'shape': 'ellipse'
            }
        },
        // 그룹 노드
        {
            selector: 'node[type = "GROUP"]',
            style: {
                'background-color': '#f59e0b',
                'border-color': '#d97706',
                'shape': 'round-rectangle'
            }
        },
        // 역할 노드
        {
            selector: 'node[type = "ROLE"]',
            style: {
                'background-color': '#a78bfa',
                'border-color': '#7c3aed',
                'shape': 'round-rectangle'
            }
        },
        // 권한 노드
        {
            selector: 'node[type = "PERMISSION"]',
            style: {
                'background-color': '#ef4444',
                'border-color': '#dc2626',
                'shape': 'diamond'
            }
        },
        // 누락된 노드
        {
            selector: 'node[type = "MISSING"]',
            style: {
                'background-color': '#64748b',
                'border-color': '#334155',
                'shape': 'hexagon',
                'opacity': 0.6
            }
        },
        // 선택된 노드
        {
            selector: ':selected',
            style: {
                'border-color': '#fbbf24',
                'border-width': 6,
                'z-index': 999
            }
        },
        // 기본 엣지 스타일
        {
            selector: 'edge',
            style: {
                'width': 3,
                'line-color': '#94a3b8',
                'target-arrow-color': '#fbbf24',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                'label': 'data(type)',
                'font-size': 12,
                'color': '#fbbf24',
                'text-background-color': '#1e293b',
                'text-background-opacity': 0.7,
                'text-background-padding': 2
            }
        },
        // 검토 필요한 엣지
        {
            selector: 'edge[reviewNeeded = true]',
            style: {
                'line-color': '#f87171',
                'target-arrow-color': '#f87171',
                'width': 5
            }
        }
    ];
}

function getHierarchicalLayout() {
    return {
        name: 'dagre',
        rankDir: 'TB',
        nodeSep: 60,
        rankSep: 80,
        edgeSep: 20,
        animate: true,
        animationDuration: 800,
        fit: true,
        padding: 40,
        spacingFactor: 1.2,
        avoidOverlap: true,
        nodeDimensionsIncludeLabels: true
    };
}

/**
 * 🔥 Cytoscape 이벤트 설정
 */
function setupCytoscapeEvents(cy) {
    // 노드 선택 이벤트
    cy.on('select', 'node', function(evt) {
        const node = evt.target;
        showNodeDetailsPanel(node.data(), evt.originalEvent);
    });
    
    cy.on('unselect', 'node', function() {
        hideDetailsPanel();
    });
    
    // 엣지 선택 이벤트
    cy.on('select', 'edge', function(evt) {
        const edge = evt.target;
        showEdgeTooltip(edge.data(), evt.originalEvent);
    });
    
    cy.on('unselect', 'edge', function() {
        hideEdgeTooltip();
    });

    // 줌 이벤트
    cy.on('zoom', function(evt) {
        const zoom = cy.zoom();
        adjustLabelsForZoom(zoom);
    });
}

/**
 * 🔥 노드 상세 정보 패널 표시
 */
function showNodeDetailsPanel(nodeData, event) {
    const detailsPanel = getOrCreateDetailsPanel();
    
    const html = `
        <div class="node-details">
            <div class="details-header">
                <i class="fas fa-info-circle text-blue-400"></i>
                <h4>${nodeData.type} 상세 정보</h4>
            </div>
            <div class="details-content">
                <div class="detail-item">
                    <span class="detail-label">이름:</span>
                    <span class="detail-value">${nodeData.label}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">유형:</span>
                    <span class="detail-value">${nodeData.type}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">권한 보유:</span>
                    <span class="detail-value ${nodeData.hasPermission ? 'text-green-400' : 'text-red-400'}">
                        ${nodeData.hasPermission ? '예' : '아니오'}
                    </span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">신뢰도:</span>
                    <span class="detail-value">${(nodeData.confidence * 100).toFixed(1)}%</span>
                </div>
            </div>
        </div>
    `;
    
    detailsPanel.innerHTML = html;
    detailsPanel.classList.remove('hidden');
    
    // 5초 후 자동 숨김
    setTimeout(() => {
        hideDetailsPanel();
    }, 5000);
}

/**
 * 🔥 엣지 툴팁 표시
 */
function showEdgeTooltip(edgeData, event) {
    const tooltip = getOrCreateTooltip('edge-tooltip');
    
    const html = `
        <div class="edge-tooltip">
            <div class="tooltip-header">
                <i class="fas fa-link text-blue-400"></i>
                <span>${edgeData.type}</span>
            </div>
            <div class="tooltip-content">
                <div class="tooltip-item">
                    <span class="tooltip-label">권한:</span>
                    <span class="tooltip-value ${edgeData.hasPermission ? 'text-green-400' : 'text-red-400'}">
                        ${edgeData.hasPermission ? '보유' : '미보유'}
                    </span>
                </div>
            </div>
        </div>
    `;
    
    tooltip.innerHTML = html;
    tooltip.classList.remove('hidden');
    
    // 위치 설정
    positionTooltip(tooltip, event);
    
    // 3초 후 자동 숨김
    setTimeout(() => {
        hideEdgeTooltip();
    }, 3000);
}

/**
 * 🔥 툴팁 생성 또는 가져오기
 */
function getOrCreateTooltip(id) {
    let tooltip = document.getElementById(id);
    if (!tooltip) {
        tooltip = document.createElement('div');
        tooltip.id = id;
        tooltip.className = 'fixed z-50 bg-slate-800 border border-slate-600 rounded-lg p-3 text-sm text-slate-200 shadow-lg hidden';
        document.body.appendChild(tooltip);
    }
    return tooltip;
}

/**
 * 🔥 상세 정보 패널 생성 또는 가져오기
 */
function getOrCreateDetailsPanel() {
    let panel = document.getElementById('details-panel');
    if (!panel) {
        panel = document.createElement('div');
        panel.id = 'details-panel';
        panel.className = 'fixed top-4 right-4 w-80 bg-slate-800 border border-slate-600 rounded-lg p-4 text-sm text-slate-200 shadow-lg z-50 hidden';
        document.body.appendChild(panel);
    }
    return panel;
}

/**
 * 🔥 툴팁 위치 설정
 */
function positionTooltip(tooltip, event) {
    const rect = tooltip.getBoundingClientRect();
    const x = event.renderedPosition.x + 10;
    const y = event.renderedPosition.y - rect.height - 10;
    
    tooltip.style.left = `${x}px`;
    tooltip.style.top = `${y}px`;
}

/**
 * 🔥 노드 툴팁 숨기기
 */
function hideNodeTooltip() {
    const tooltip = document.getElementById('node-tooltip');
    if (tooltip) {
        tooltip.classList.add('hidden');
    }
}

/**
 * 🔥 엣지 툴팁 숨기기
 */
function hideEdgeTooltip() {
    const tooltip = document.getElementById('edge-tooltip');
    if (tooltip) {
        tooltip.classList.add('hidden');
    }
}

/**
 * 🔥 상세 정보 패널 숨기기
 */
function hideDetailsPanel() {
    const panel = document.getElementById('details-panel');
    if (panel) {
        panel.classList.add('hidden');
    }
}

/**
 * 🔥 Cytoscape 오류 표시
 */
function showCytoscapeError(container, error) {
    // 컨테이너가 유효한지 확인
    if (!container || !(container instanceof Element)) {
        console.error('유효하지 않은 컨테이너:', container);
        return;
    }
    
    container.innerHTML = `
        <div class="cytoscape-error">
            <div class="error-header">
                <i class="fas fa-exclamation-triangle text-red-400"></i>
                <h4>시각화 오류</h4>
            </div>
            <div class="error-content">
                <p class="error-message">시각화를 생성하는 중 오류가 발생했습니다.</p>
                <p class="error-details">${error.message}</p>
            </div>
        </div>
    `;
}

/**
 * 🔥 줌에 따른 라벨 조정
 */
function adjustLabelsForZoom(zoom) {
    if (!window.cytoscapeInstance) return;
    
    const cy = window.cytoscapeInstance;
    const zoomLevel = zoom.level;
    
    // 줌 레벨에 따라 폰트 크기 조정
    const fontSize = Math.max(8, Math.min(16, 12 * zoomLevel));
    
    cy.style().selector('node').style({
        'font-size': `${fontSize}px`
    }).update();
}

/**
 * 🔥 AI 시각화 오버레이 생성
 */
function createAIVisualizationOverlay(analysisResult, visualizationData) {
    console.log('🎯 AI 시각화 오버레이 생성');
    
    // AI 분석 결과를 시각화에 반영
    if (analysisResult.insights && analysisResult.insights.length > 0) {
        // 인사이트를 시각화에 표시
        console.log('📊 AI 인사이트를 시각화에 반영:', analysisResult.insights);
    }
    
    if (analysisResult.suggestions && analysisResult.suggestions.length > 0) {
        // 권장사항을 시각화에 표시
        console.log('💡 AI 권장사항을 시각화에 반영:', analysisResult.suggestions);
    }
}

/**
 * 🔥 상세 리포트 표시
 */
function showDetailedReport(analysisResult) {
    console.log('📊 상세 리포트 표시:', analysisResult);
    
    // 모달 생성
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
    modal.innerHTML = `
        <div class="bg-slate-800 border border-slate-600 rounded-lg p-6 max-w-4xl mx-4 max-h-[90vh] overflow-y-auto">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-xl font-bold text-slate-200">
                    <i class="fas fa-chart-pie text-blue-400 mr-2"></i>
                    상세 분석 리포트
                </h3>
                <button onclick="this.closest('.fixed').remove()" class="text-slate-400 hover:text-white">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="report-content">
                <p class="text-slate-300">상세 리포트 내용이 여기에 표시됩니다.</p>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

/**
 * 🔥 상세 통계 표시
 */
function showDetailedStatistics(analysisResult) {
    console.log('📊 상세 통계 표시:', analysisResult);
    
    // 모달 생성
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
    modal.innerHTML = `
        <div class="bg-slate-800 border border-slate-600 rounded-lg p-6 max-w-4xl mx-4 max-h-[90vh] overflow-y-auto">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-xl font-bold text-slate-200">
                    <i class="fas fa-chart-bar text-blue-400 mr-2"></i>
                    상세 통계 분석
                </h3>
                <button onclick="this.closest('.fixed').remove()" class="text-slate-400 hover:text-white">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="statistics-content">
                <p class="text-slate-300">상세 통계 내용이 여기에 표시됩니다.</p>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

/**
 * 🎯 권한 거버넌스 전용 인터랙티브 기능 활성화
 */
function enableGovernanceInteractions(analysisResult) {
    // 상세 리포트 버튼 이벤트
    const detailedReportBtn = document.querySelector('.detailed-report-btn');
    if (detailedReportBtn) {
        detailedReportBtn.onclick = () => showDetailedGovernanceReport(analysisResult);
    }

    // 발견 사항 클릭 이벤트
    document.querySelectorAll('.finding-item').forEach(item => {
        item.addEventListener('click', function() {
            const findingType = this.querySelector('h5').textContent;
            showFindingDetails(findingType, analysisResult);
        });
    });

    // 권장사항 클릭 이벤트
    document.querySelectorAll('.recommendation-item').forEach(item => {
        item.addEventListener('click', function() {
            const recommendationTitle = this.querySelector('h5').textContent;
            showRecommendationDetails(recommendationTitle, analysisResult);
        });
    });

    // 액션 아이템 클릭 이벤트
    document.querySelectorAll('.action-item').forEach(item => {
        item.addEventListener('click', function() {
            const actionTitle = this.querySelector('h5').textContent;
            showActionItemDetails(actionTitle, analysisResult);
        });
    });
}

/**
 * 🔥 상세 권한 거버넌스 리포트 표시
 */
function showDetailedGovernanceReport(analysisResult) {
    console.log('📊 상세 권한 거버넌스 리포트 표시:', analysisResult);
    
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
    modal.innerHTML = `
        <div class="bg-slate-800 border border-slate-600 rounded-lg p-6 max-w-6xl mx-4 max-h-[90vh] overflow-y-auto">
            <div class="flex items-center justify-between mb-6">
                <h3 class="text-2xl font-bold text-slate-200">
                    <i class="fas fa-shield-alt text-blue-400 mr-3"></i>
                    권한 거버넌스 상세 분석 리포트
                </h3>
                <button onclick="this.closest('.fixed').remove()" class="text-slate-400 hover:text-white text-xl">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            
            <div class="report-content space-y-6">
                <!-- 거버넌스 점수 섹션 -->
                <div class="governance-score-detail bg-slate-700/50 rounded-lg p-4">
                    <h4 class="text-lg font-semibold text-slate-200 mb-3">
                        <i class="fas fa-chart-line text-blue-400 mr-2"></i>
                        거버넌스 점수 상세 분석
                    </h4>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div class="score-card bg-slate-600/50 rounded-lg p-3">
                            <div class="text-center">
                                <div class="text-3xl font-bold text-blue-400">${analysisResult.overallGovernanceScore?.toFixed(1) || 'N/A'}</div>
                                <div class="text-sm text-slate-300">거버넌스 점수</div>
                            </div>
                        </div>
                        <div class="score-card bg-slate-600/50 rounded-lg p-3">
                            <div class="text-center">
                                <div class="text-3xl font-bold ${getRiskLevelColor(analysisResult.riskLevel)}">${getRiskLevelText(analysisResult.riskLevel)}</div>
                                <div class="text-sm text-slate-300">위험도</div>
                            </div>
                        </div>
                        <div class="score-card bg-slate-600/50 rounded-lg p-3">
                            <div class="text-center">
                                <div class="text-3xl font-bold text-green-400">${(analysisResult.findings || []).length}</div>
                                <div class="text-sm text-slate-300">발견 사항</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 발견 사항 상세 -->
                <div class="findings-detail bg-slate-700/50 rounded-lg p-4">
                    <h4 class="text-lg font-semibold text-slate-200 mb-3">
                        <i class="fas fa-search text-blue-400 mr-2"></i>
                        발견 사항 상세 분석
                    </h4>
                    <div class="space-y-3">
                        ${(analysisResult.findings || []).map(finding => `
                            <div class="finding-detail-item bg-slate-600/50 rounded-lg p-3">
                                <div class="flex items-center justify-between mb-2">
                                    <h5 class="text-slate-200 font-medium">${finding.type || '이상 징후'}</h5>
                                    <span class="severity-badge ${getSeverityColor(finding.severity)} text-xs px-2 py-1 rounded">
                                        ${getSeverityText(finding.severity)}
                                    </span>
                                </div>
                                <p class="text-slate-300 text-sm mb-2">${finding.description || '설명 없음'}</p>
                                <div class="text-xs text-slate-400">
                                    <div>영향 사용자: ${(finding.affectedUsers || []).join(', ') || 'N/A'}</div>
                                    <div>영향 역할: ${(finding.affectedRoles || []).join(', ') || 'N/A'}</div>
                                    <div>권장사항: ${finding.recommendation || 'N/A'}</div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <!-- 권장사항 상세 -->
                <div class="recommendations-detail bg-slate-700/50 rounded-lg p-4">
                    <h4 class="text-lg font-semibold text-slate-200 mb-3">
                        <i class="fas fa-lightbulb text-yellow-400 mr-2"></i>
                        권장사항 상세 분석
                    </h4>
                    <div class="space-y-3">
                        ${(analysisResult.recommendations || []).map(rec => `
                            <div class="recommendation-detail-item bg-slate-600/50 rounded-lg p-3">
                                <div class="flex items-center justify-between mb-2">
                                    <h5 class="text-slate-200 font-medium">${rec.title || rec.category || '권장사항'}</h5>
                                    <span class="priority-badge ${getPriorityColor(rec.priority)} text-xs px-2 py-1 rounded">
                                        ${getPriorityText(rec.priority)}
                                    </span>
                                </div>
                                <p class="text-slate-300 text-sm mb-2">${rec.description || '설명 없음'}</p>
                                ${rec.implementationSteps && rec.implementationSteps.length > 0 ? `
                                    <div class="implementation-steps text-xs text-slate-400">
                                        <strong>구현 단계:</strong>
                                        <ol class="list-decimal list-inside mt-1">
                                            ${rec.implementationSteps.map(step => `<li>${step}</li>`).join('')}
                                        </ol>
                                    </div>
                                ` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>

                <!-- 액션 아이템 상세 -->
                <div class="action-items-detail bg-slate-700/50 rounded-lg p-4">
                    <h4 class="text-lg font-semibold text-slate-200 mb-3">
                        <i class="fas fa-tasks text-green-400 mr-2"></i>
                        액션 아이템 상세 분석
                    </h4>
                    <div class="space-y-3">
                        ${(analysisResult.actionItems || []).map(item => `
                            <div class="action-item-detail bg-slate-600/50 rounded-lg p-3">
                                <div class="flex items-center justify-between mb-2">
                                    <h5 class="text-slate-200 font-medium">${item.title || '액션 아이템'}</h5>
                                    <span class="status-badge ${getStatusColor(item.status)} text-xs px-2 py-1 rounded">
                                        ${getStatusText(item.status)}
                                    </span>
                                </div>
                                <p class="text-slate-300 text-sm mb-2">${item.description || '설명 없음'}</p>
                                <div class="text-xs text-slate-400">
                                    <div>담당자: ${item.assignee || 'N/A'}</div>
                                    <div>기한: ${item.dueDate || 'N/A'}</div>
                                    <div>ID: ${item.id || 'N/A'}</div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <!-- 통계 상세 -->
                <div class="statistics-detail bg-slate-700/50 rounded-lg p-4">
                    <h4 class="text-lg font-semibold text-slate-200 mb-3">
                        <i class="fas fa-chart-bar text-purple-400 mr-2"></i>
                        통계 상세 분석
                    </h4>
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                        ${Object.entries(analysisResult.statistics || {}).map(([key, value]) => `
                            <div class="stat-card bg-slate-600/50 rounded-lg p-3 text-center">
                                <div class="text-2xl font-bold text-purple-400">${typeof value === 'number' ? value.toLocaleString() : value}</div>
                                <div class="text-xs text-slate-300">${getStatisticsDisplayName(key)}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

/**
 * 발견 사항 상세 정보 표시
 */
function showFindingDetails(findingType, analysisResult) {
    const finding = (analysisResult.findings || []).find(f => f.type === findingType);
    if (!finding) return;

    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
    modal.innerHTML = `
        <div class="bg-slate-800 border border-slate-600 rounded-lg p-6 max-w-2xl mx-4">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-xl font-bold text-slate-200">
                    <i class="fas fa-search text-blue-400 mr-2"></i>
                    발견 사항 상세 정보
                </h3>
                <button onclick="this.closest('.fixed').remove()" class="text-slate-400 hover:text-white">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="finding-detail-content">
                <div class="mb-4">
                    <h4 class="text-slate-200 font-semibold mb-2">${finding.type}</h4>
                    <p class="text-slate-300 text-sm">${finding.description}</p>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                        <strong class="text-slate-200">심각도:</strong>
                        <span class="text-slate-300 ml-2">${getSeverityText(finding.severity)}</span>
                    </div>
                    <div>
                        <strong class="text-slate-200">영향 사용자:</strong>
                        <span class="text-slate-300 ml-2">${(finding.affectedUsers || []).join(', ') || 'N/A'}</span>
                    </div>
                    <div>
                        <strong class="text-slate-200">영향 역할:</strong>
                        <span class="text-slate-300 ml-2">${(finding.affectedRoles || []).join(', ') || 'N/A'}</span>
                    </div>
                    <div>
                        <strong class="text-slate-200">권장사항:</strong>
                        <span class="text-slate-300 ml-2">${finding.recommendation || 'N/A'}</span>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

/**
 * 💡 권장사항 상세 정보 표시
 */
function showRecommendationDetails(recommendationTitle, analysisResult) {
    const recommendation = (analysisResult.recommendations || []).find(r => r.title === recommendationTitle);
    if (!recommendation) return;

    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
    modal.innerHTML = `
        <div class="bg-slate-800 border border-slate-600 rounded-lg p-6 max-w-2xl mx-4">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-xl font-bold text-slate-200">
                    <i class="fas fa-lightbulb text-yellow-400 mr-2"></i>
                    권장사항 상세 정보
                </h3>
                <button onclick="this.closest('.fixed').remove()" class="text-slate-400 hover:text-white">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="recommendation-detail-content">
                <div class="mb-4">
                    <h4 class="text-slate-200 font-semibold mb-2">${recommendation.title || recommendation.category}</h4>
                    <p class="text-slate-300 text-sm">${recommendation.description}</p>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                        <strong class="text-slate-200">우선순위:</strong>
                        <span class="text-slate-300 ml-2">${getPriorityText(recommendation.priority)}</span>
                    </div>
                    <div>
                        <strong class="text-slate-200">카테고리:</strong>
                        <span class="text-slate-300 ml-2">${recommendation.category || 'N/A'}</span>
                    </div>
                </div>
                ${recommendation.implementationSteps && recommendation.implementationSteps.length > 0 ? `
                    <div class="mt-4">
                        <strong class="text-slate-200">구현 단계:</strong>
                        <ol class="list-decimal list-inside mt-2 text-slate-300 text-sm">
                            ${recommendation.implementationSteps.map(step => `<li>${step}</li>`).join('')}
                        </ol>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

/**
 * 액션 아이템 상세 정보 표시
 */
function showActionItemDetails(actionTitle, analysisResult) {
    const actionItem = (analysisResult.actionItems || []).find(a => a.title === actionTitle);
    if (!actionItem) return;

    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
    modal.innerHTML = `
        <div class="bg-slate-800 border border-slate-600 rounded-lg p-6 max-w-2xl mx-4">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-xl font-bold text-slate-200">
                    <i class="fas fa-tasks text-green-400 mr-2"></i>
                    액션 아이템 상세 정보
                </h3>
                <button onclick="this.closest('.fixed').remove()" class="text-slate-400 hover:text-white">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="action-item-detail-content">
                <div class="mb-4">
                    <h4 class="text-slate-200 font-semibold mb-2">${actionItem.title}</h4>
                    <p class="text-slate-300 text-sm">${actionItem.description}</p>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                        <strong class="text-slate-200">상태:</strong>
                        <span class="text-slate-300 ml-2">${getStatusText(actionItem.status)}</span>
                    </div>
                    <div>
                        <strong class="text-slate-200">담당자:</strong>
                        <span class="text-slate-300 ml-2">${actionItem.assignee || 'N/A'}</span>
                    </div>
                    <div>
                        <strong class="text-slate-200">기한:</strong>
                        <span class="text-slate-300 ml-2">${actionItem.dueDate || 'N/A'}</span>
                    </div>
                    <div>
                        <strong class="text-slate-200">ID:</strong>
                        <span class="text-slate-300 ml-2">${actionItem.id || 'N/A'}</span>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

/**
 * 🔥 헬퍼 함수들
 */
function getRiskLevelText(riskLevel) {
    const riskTexts = {
        'LOW': '낮음',
        'MEDIUM': '중간',
        'HIGH': '높음',
        'CRITICAL': '매우 높음',
        'UNKNOWN': '알 수 없음'
    };
    return riskTexts[riskLevel] || '알 수 없음';
}

function getRiskLevelColor(riskLevel) {
    const riskColors = {
        'LOW': 'text-green-400',
        'MEDIUM': 'text-yellow-400',
        'HIGH': 'text-orange-400',
        'CRITICAL': 'text-red-400',
        'UNKNOWN': 'text-gray-400'
    };
    return riskColors[riskLevel] || 'text-gray-400';
}

function getSeverityText(severity) {
    const severityTexts = {
        'LOW': '낮음',
        'MEDIUM': '중간',
        'HIGH': '높음',
        'CRITICAL': '매우 높음'
    };
    return severityTexts[severity] || '알 수 없음';
}

function getSeverityColor(severity) {
    const severityColors = {
        'LOW': 'text-blue-400',
        'MEDIUM': 'text-yellow-400',
        'HIGH': 'text-red-400',
        'CRITICAL': 'text-red-600'
    };
    return severityColors[severity] || 'text-gray-400';
}

function getPriorityText(priority) {
    const priorityTexts = {
        'LOW': '낮음',
        'MEDIUM': '중간',
        'HIGH': '높음',
        'CRITICAL': '매우 높음'
    };
    return priorityTexts[priority] || '알 수 없음';
}

function getPriorityColor(priority) {
    const priorityColors = {
        'LOW': 'text-blue-400',
        'MEDIUM': 'text-yellow-400',
        'HIGH': 'text-red-400',
        'CRITICAL': 'text-red-600'
    };
    return priorityColors[priority] || 'text-gray-400';
}

function getStatusText(status) {
    const statusTexts = {
        'PENDING': '대기 중',
        'IN_PROGRESS': '진행 중',
        'COMPLETED': '완료',
        'CANCELLED': '취소됨'
    };
    return statusTexts[status] || '알 수 없음';
}

function getStatusColor(status) {
    const statusColors = {
        'PENDING': 'text-yellow-400',
        'IN_PROGRESS': 'text-blue-400',
        'COMPLETED': 'text-green-400',
        'CANCELLED': 'text-red-400'
    };
    return statusColors[status] || 'text-gray-400';
}

function getStatisticsDisplayName(key) {
    const displayNames = {
        'totalUsers': '총 사용자',
        'totalRoles': '총 역할',
        'totalGroups': '총 그룹',
        'totalPermissions': '총 권한',
        'dormantPermissions': '미사용 권한',
        'excessivePermissions': '과도한 권한',
        'sodViolations': '업무 분리 위반',
        'emptyRoles': '빈 역할',
        'emptyGroups': '빈 그룹',
        'overallGovernanceScore': '거버넌스 점수',
        'riskLevel': '위험도',
        'totalFindings': '총 발견 사항',
        'criticalFindings': '중요 발견 사항',
        'totalRecommendations': '총 권장사항',
        'highPriorityRecommendations': '높은 우선순위 권장사항'
    };
    return displayNames[key] || key;
}


function showFullscreenDiagram() {
    if (!cytoscapeInstance) {
        showError('다이어그램이 아직 생성되지 않았습니다.');
        return;
    }
    
    try {
        const modal = document.getElementById('fullscreen-modal');
        if (!modal) {
            showError('전체보기 모달을 찾을 수 없습니다.');
            return;
        }
        
        modal.classList.remove('hidden');
        
        // 다이어그램 복제 렌더링
        const fsCanvas = document.getElementById('fullscreen-canvas');
        if (!fsCanvas) {
            showError('전체보기 캔버스를 찾을 수 없습니다.');
            return;
        }
        
        fsCanvas.innerHTML = '';
        
        // cytoscapeInstance.json()이 null일 수 있으므로 안전하게 처리
        let elements;
        try {
            const jsonData = cytoscapeInstance.json();
            elements = jsonData ? jsonData.elements : cytoscapeInstance.elements().map(ele => ele.json());
        } catch (e) {
            elements = cytoscapeInstance.elements().map(ele => ele.json());
        }
        
        fullscreenCytoscapeInstance = window.cytoscape({
            container: fsCanvas,
            elements: elements,
            style: getCytoscapeStyles(),
            layout: getHierarchicalLayout(),
            boxSelectionEnabled: false,
            autoungrabify: false,
            wheelSensitivity: 0.5
        });
        
        setupCytoscapeEvents(fullscreenCytoscapeInstance);
        currentZoomLevel = 1.0;
        updateZoomLevelDisplay();
        bindZoomEvents();
        
    } catch (error) {
        console.error('전체보기 다이어그램 오류:', error);
        showError('전체보기 다이어그램을 생성하는 중 오류가 발생했습니다.');
    }
}
// 닫기 버튼/ESC키 이벤트
const closeBtn = document.getElementById('fullscreen-close-btn');
if (closeBtn) {
    closeBtn.onclick = closeFullscreenDiagram;
}
function closeFullscreenDiagram() {
    const modal = document.getElementById('fullscreen-modal');
    if (modal) modal.classList.add('hidden');
    if (fullscreenCytoscapeInstance) {
        fullscreenCytoscapeInstance.destroy();
        fullscreenCytoscapeInstance = null;
    }
}
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeFullscreenDiagram();
});
// 줌 컨트롤
function updateZoomLevelDisplay() {
    const zoomLevelSpan = document.querySelector('#fullscreen-modal .zoom-level');
    if (zoomLevelSpan && fullscreenCytoscapeInstance) {
        const percent = Math.round(fullscreenCytoscapeInstance.zoom() * 100);
        zoomLevelSpan.textContent = percent + '%';
    }
}
function bindZoomEvents() {
    const inBtn = document.querySelector('#fullscreen-modal .zoom-in');
    const outBtn = document.querySelector('#fullscreen-modal .zoom-out');
    const resetBtn = document.querySelector('#fullscreen-modal .zoom-reset');
    if (inBtn) inBtn.onclick = () => {
        if (fullscreenCytoscapeInstance) {
            fullscreenCytoscapeInstance.zoom(fullscreenCytoscapeInstance.zoom() * 1.2);
            updateZoomLevelDisplay();
        }
    };
    if (outBtn) outBtn.onclick = () => {
        if (fullscreenCytoscapeInstance) {
            fullscreenCytoscapeInstance.zoom(fullscreenCytoscapeInstance.zoom() / 1.2);
            updateZoomLevelDisplay();
        }
    };
    if (resetBtn) resetBtn.onclick = () => {
        if (fullscreenCytoscapeInstance) {
            fullscreenCytoscapeInstance.zoom(1);
            fullscreenCytoscapeInstance.center();
            updateZoomLevelDisplay();
        }
    };
}
document.getElementById('fullscreen-modal')?.addEventListener('click', function(e) {
    if (e.target === this) closeFullscreenDiagram();
});
// 전체보기 모달 열릴 때마다 바인딩
const observer = new MutationObserver(() => {
    if (!document.getElementById('fullscreen-modal').classList.contains('hidden')) {
        bindZoomEvents();
    }
});
observer.observe(document.getElementById('fullscreen-modal'), { attributes: true, attributeFilter: ['class'] });

 