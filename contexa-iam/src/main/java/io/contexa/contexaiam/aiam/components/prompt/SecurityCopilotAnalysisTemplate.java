package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacore.std.components.prompt.PromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptTemplateConfig;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.context.SecurityCopilotContext;
import io.contexa.contexaiam.aiam.protocol.response.SecurityCopilotResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;


@Slf4j
@PromptTemplateConfig(
        key = "securityCopilotAnalysis",
        aliases = {"security_copilot", "comprehensive_security_analysis"},
        description = "Spring AI Structured Output Security Copilot Analysis Template"
)
public class SecurityCopilotAnalysisTemplate implements PromptTemplate {
    
    
    private final BeanOutputConverter<SecurityCopilotResponse> converter = 
        new BeanOutputConverter<>(SecurityCopilotResponse.class);

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        log.debug("SecurityCopilot 분석 시스템 프롬프트 생성 시작");
        
        
        String formatInstructions = converter.getFormat();

        return String.format("""
            You are a Security Copilot AI specialized in comprehensive IAM security analysis by integrating multiple specialized analysis systems.
            
            IMPORTANT: Response must be in PURE JSON format matching the SecurityCopilotResponse schema.
            Language: All text fields must be in Korean (한국어).
            
            <mission>
            핵심 임무: 다중 Lab 분석 결과를 통합하여 종합적인 보안 평가 제공
            
            분석 영역:
            1. 권한 구조 분석 (StudioQuery Lab)
            2. 위험도 평가 (RiskAssessment Lab)  
            3. 정책 권장사항 (PolicyGeneration Lab)
            </mission>
            
            <security_analysis_framework>
            보안 분석 프레임워크:
            
            **1. 권한 구조 분석 (20점)**
            - 사용자 권한 적절성 (5점)
            - 역할 기반 접근제어 효율성 (5점)
            - 권한 상속 구조 건전성 (5점)  
            - 최소 권한 원칙 준수 (5점)
            
            **2. 위험도 평가 (25점)**
            - 과도한 권한 위험 (10점)
            - 비활성 계정 위험 (5점)
            - 권한 충돌 위험 (5점)
            - 컴플라이언스 위험 (5점)
            
            **3. 정책 효율성 (20점)**  
            - 정책 구조 최적화 (10점)
            - 조건 설정 적절성 (5점)
            - 정책 충돌 최소화 (5점)
            
            **4. 운영 효율성 (15점)**
            - 리소스 명명 일관성 (7점)
            - 관리 용이성 (8점)
            
            **5. 보안 거버넌스 (20점)**
            - 감사 추적 가능성 (10점)
            - 정책 변경 관리 (5점)
            - 사용자 교육 필요성 (5점)
            
            **총합: 100점 만점**
            </security_analysis_framework>
            
            <risk_levels>
            위험 등급 분류:
            - 🟢 낮음 (80-100점): 우수한 보안 상태
            - 🟡 중간 (60-79점): 일반적인 보안 수준, 일부 개선 필요
            - 🟠 높음 (40-59점): 중요한 보안 취약점 존재
            - 🔴 심각 (0-39점): 즉시 조치가 필요한 심각한 보안 위험
            </risk_levels>
            
            <output_format>
            💡 응답 형식 (반드시 JSON 구조로만 응답):
            
            ===JSON시작===
            {
              "overallSecurityScore": 75.5,
              "riskLevel": "HIGH",
              "structureAnalysis": "권한 구조 분석 결과 상세 설명",
              "riskAnalysis": "위험 분석 결과 상세 설명",
              "actionPlan": "권장사항 및 조치 계획",
              "categoryScores": {
                "permissionStructure": 18,
                "riskAssessment": 20,
                "policyEfficiency": 15,
                "operationalEfficiency": 12,
                "securityGovernance": 16
              },
              "complianceInfo": {
                "overallScore": 85.0,
                "status": "부분준수"
              },
              "metadata": {
                "recommendations": [
                  {
                    "title": "보안 정책 강화",
                    "description": "현재 권한 정책이 과도하게 허용적으로 설정되어 있어 최소 권한 원칙을 위반하고 있습니다. 각 사용자별로 업무에 필요한 최소한의 권한만 부여하도록 정책을 재설계해야 합니다.",
                    "priority": "high",
                    "category": "policy",
                    "assignee": "보안 관리자",
                    "deadline": "2024-01-15",
                    "estimatedEffort": "2주",
                    "expectedImpact": "보안 위험 40% 감소"
                  },
                  {
                    "title": "권한 관리 프로세스 개선",
                    "description": "사용자 권한 할당 및 해제 프로세스가 체계적이지 않아 불필요한 권한이 누적되고 있습니다. 정기적인 권한 검토 및 자동화된 권한 관리 시스템을 도입해야 합니다.",
                    "priority": "medium",
                    "category": "process",
                    "assignee": "시스템 관리자",
                    "deadline": "2024-01-30",
                    "estimatedEffort": "3주",
                    "expectedImpact": "권한 관리 효율성 60% 향상"
                  },
                  {
                    "title": "보안 모니터링 강화",
                    "description": "현재 보안 이벤트 모니터링이 부족하여 이상 행위 탐지가 어려운 상황입니다. 실시간 모니터링 시스템을 구축하여 보안 위협을 조기에 탐지할 수 있도록 해야 합니다.",
                    "priority": "high",
                    "category": "monitoring",
                    "assignee": "보안 운영팀",
                    "deadline": "2024-02-15",
                    "estimatedEffort": "4주",
                    "expectedImpact": "보안 위협 탐지율 80% 향상"
                  }
                ],
                "criticalFindings": [
                  {
                    "title": "과도한 관리자 권한 부여",
                    "description": "일반 사용자에게 관리자 권한이 부여되어 있어 시스템 전체에 심각한 보안 위험을 초래하고 있습니다. 즉시 권한을 재검토하고 필요한 경우에만 제한적으로 부여해야 합니다.",
                    "severity": "critical",
                    "category": "permission",
                    "affectedUsers": 15,
                    "riskScore": 95,
                    "businessImpact": "시스템 전체 보안 침해 가능성",
                    "immediateAction": "관리자 권한 즉시 회수 및 재검토"
                  },
                  {
                    "title": "비활성 계정 방치",
                    "description": "90일 이상 사용되지 않은 계정이 여전히 활성화되어 있어 불법 접근의 통로로 악용될 수 있습니다. 정기적인 계정 정리 프로세스가 필요합니다.",
                    "severity": "high",
                    "category": "account",
                    "affectedUsers": 23,
                    "riskScore": 75,
                    "businessImpact": "무단 접근 및 데이터 유출 위험",
                    "immediateAction": "비활성 계정 즉시 비활성화"
                  },
                  {
                    "title": "권한 충돌 및 중복",
                    "description": "동일한 사용자에게 상충되는 권한이 부여되어 있어 보안 정책의 일관성이 훼손되고 있습니다. 권한 매트릭스를 재정비하여 충돌을 해결해야 합니다.",
                    "severity": "medium",
                    "category": "policy",
                    "affectedUsers": 8,
                    "riskScore": 60,
                    "businessImpact": "보안 정책 우회 가능성",
                    "immediateAction": "권한 충돌 분석 및 정리"
                  }
                ],
                "nextActions": [
                  "우선순위 1: 즉시 조치사항 - 24시간 내 완료",
                  "우선순위 2: 단기 개선사항 - 1주일 내 완료", 
                  "우선순위 3: 장기 개선사항 - 1개월 내 완료"
                ],
                "complianceStatus": {
                  "ISMS_P": "준수",
                  "ISO_27001": "부분준수",
                  "GDPR": "준수"
                },
                "securityMetrics": {
                  "totalUsers": 0,
                  "totalRoles": 0,
                  "totalPermissions": 0,
                  "riskScore": 0,
                  "complianceScore": 0
                },
                "analysisDetails": {
                  "analysisDate": "2024-01-01",
                  "analysisType": "comprehensive",
                  "dataSource": "실시간 시스템 데이터",
                  "coveragePercentage": 100
                }
              },
              "recommendationSummary": "종합 보안 분석 결과: 전체 보안 점수 XX점으로 [위험수준]입니다. 주요 개선 필요 영역은 [구체적 영역]이며, 즉시 조치가 필요한 사항은 [구체적 사항]입니다. 권장 조치 순서: 1) [즉시 조치], 2) [단기 개선], 3) [장기 개선]. 예상 개선 효과: [구체적 효과]."
            }
            ===JSON끝===
            </output_format>
            
            <analysis_principles>
            분석 원칙:
            1. 객관적이고 정확한 보안 점수 산출
            2. 구체적이고 실행 가능한 권장사항 제시
            3. 위험도에 따른 우선순위 명확화
            4. 컴플라이언스 기준 준수 상태 평가
            5. 비즈니스 영향도 고려한 균형잡힌 분석
            </analysis_principles>
            
            %s
            
            %s
            
            Critical Rules:
            1. Perfect JSON format compliance
            2. Accurate security score calculation
            3. Specific and actionable recommendations
            4. Critical findings must be clearly identified
            5. All text content in Korean
            6. No comments or explanations outside JSON
            """, formatInstructions, systemMetadata != null ? systemMetadata : "");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        log.debug("SecurityCopilot 분석 사용자 프롬프트 생성 시작");

        
        String securityQuery = extractSecurityQuery(request);
        
        
        String labResultsInfo = extractLabResultsInfo(request);
        
        
        String analysisScope = extractAnalysisScope(request);

        return buildAnalysisUserPrompt(securityQuery, labResultsInfo, analysisScope, contextInfo);
    }

    
    private String buildAnalysisUserPrompt(String securityQuery, String labResultsInfo, 
                                         String analysisScope, String contextInfo) {
        String analysisRequest =  String.format("""
            **보안 분석 요청:**
            "%s"
            
            **분석 범위:**
            %s
            
            **각 Lab 분석 결과:**
            %s
            
            **시스템 컨텍스트:**
            %s
            
            **분석 지시사항:**
            
            1. **종합 분석 수행**: 각 Lab의 분석 결과를 종합하여 전체적인 보안 상태를 평가하세요
            
            2. **정확한 점수 계산**: 
               - 권한 구조 분석: 20점 만점
               - 위험도 평가: 25점 만점  
               - 정책 효율성: 20점 만점
               - 운영 효율성: 15점 만점
               - 보안 거버넌스: 20점 만점
               - 총합: 100점 만점
            
            3. **실행 가능한 권장사항**: 구체적이고 실무에 바로 적용할 수 있는 개선 방안을 제시하세요
            
            4. **위험도 우선순위**: 심각한 보안 위험을 식별하고 우선순위를 매겨주세요
            
            5. **컴플라이언스 평가**: 주요 보안 표준 준수 상태를 평가하세요
            
            **지금 즉시 종합 보안 분석을 수행하고 JSON 형식으로 응답하세요:**
            
            ===JSON시작===
            {
              "overallSecurityScore": 0.0,
              "riskLevel": "HIGH|MEDIUM|LOW|CRITICAL",
              "structureAnalysis": "권한 구조 분석 결과 상세 설명",
              "riskAnalysis": "위험 분석 결과 상세 설명",
              "actionPlan": "권장사항 및 조치 계획",
              "categoryScores": {
                "permissionStructure": 0,
                "riskAssessment": 0,
                "policyEfficiency": 0,
                "operationalEfficiency": 0,
                "securityGovernance": 0
              },
              "complianceInfo": {
                "overallScore": 85.0,
                "status": "준수|부분준수|미준수"
              },
              "metadata": {
                "recommendations": [
                  "구체적이고 실행 가능한 권장사항 1 - 담당자와 기한 포함",
                  "구체적이고 실행 가능한 권장사항 2 - 담당자와 기한 포함",
                  "구체적이고 실행 가능한 권장사항 3 - 담당자와 기한 포함",
                  "구체적이고 실행 가능한 권장사항 4 - 담당자와 기한 포함",
                  "구체적이고 실행 가능한 권장사항 5 - 담당자와 기한 포함"
                ],
                "criticalFindings": [
                  "즉시 해결이 필요한 심각한 보안 문제 1 - 위험도와 영향 범위 포함",
                  "즉시 해결이 필요한 심각한 보안 문제 2 - 위험도와 영향 범위 포함",
                  "즉시 해결이 필요한 심각한 보안 문제 3 - 위험도와 영향 범위 포함"
                ],
                "nextActions": [
                  "우선순위 1: 즉시 조치사항 - 24시간 내 완료",
                  "우선순위 2: 단기 개선사항 - 1주일 내 완료", 
                  "우선순위 3: 장기 개선사항 - 1개월 내 완료"
                ],
                "complianceStatus": {
                  "ISMS_P": "준수|부분준수|미준수",
                  "ISO_27001": "준수|부분준수|미준수",
                  "GDPR": "준수|부분준수|미준수"
                },
                "securityMetrics": {
                  "totalUsers": 0,
                  "totalRoles": 0,
                  "totalPermissions": 0,
                  "riskScore": 0,
                  "complianceScore": 0
                },
                "analysisDetails": {
                  "analysisDate": "2024-01-01",
                  "analysisType": "comprehensive",
                  "dataSource": "실시간 시스템 데이터",
                  "coveragePercentage": 100
                }
              },
              "recommendationSummary": "종합 보안 분석 결과: 전체 보안 점수 XX점으로 [위험수준]입니다. 주요 개선 필요 영역은 [구체적 영역]이며, 즉시 조치가 필요한 사항은 [구체적 사항]입니다. 권장 조치 순서: 1) [즉시 조치], 2) [단기 개선], 3) [장기 개선]. 예상 개선 효과: [구체적 효과]."
            }
            Generate complete SecurityCopilotResponse in JSON format.
            """, 
            securityQuery, 
            analysisScope, 
            labResultsInfo, 
            contextInfo);
        
        
        return analysisRequest + "\n\n" + converter.getFormat();
    }

    
    private String extractSecurityQuery(AIRequest<? extends DomainContext> request) {
        
        String securityQuery = request.getParameter("securityQuery", String.class);
        
        if (securityQuery != null && !securityQuery.trim().isEmpty()) {
            return securityQuery;
        }
        
        
        if (request.getContext() instanceof SecurityCopilotContext) {
            SecurityCopilotContext context = (SecurityCopilotContext) request.getContext();
            return context.getSecurityQuery();
        }
        
        return "포괄적 보안 분석 요청";
    }

    
    private String extractLabResultsInfo(AIRequest<? extends DomainContext> request) {
        StringBuilder labResults = new StringBuilder();
        
        
        Boolean labCollaborationEnabled = request.getParameter("labCollaborationEnabled", Boolean.class);
        Integer labResultsCount = request.getParameter("labResultsCount", Integer.class);
        String labAnalysisId = request.getParameter("labAnalysisId", String.class);
        
        labResults.append("Lab 협업 분석 결과:\n");
        labResults.append("- 분석 ID: ").append(labAnalysisId != null ? labAnalysisId : "미제공").append("\n");
        labResults.append("- Lab 협업: ").append(labCollaborationEnabled != null && labCollaborationEnabled ? "활성화" : "비활성화").append("\n");
        labResults.append("- 참여 Lab 수: ").append(labResultsCount != null ? labResultsCount : 0).append("개\n\n");
        
        String[] labNames = {"StudioQuery", "RiskAssessment", "PolicyGeneration"};
        String[] labIcons = {"🧠", "⚠️", "📋"};
        
        boolean hasResults = false;
        for (int i = 0; i < labNames.length; i++) {
            String paramName = "labResult_" + labNames[i];
            Object labResult = request.getParameter(paramName, Object.class);
            
            if (labResult != null) {
                hasResults = true;
                labResults.append(labIcons[i]).append(" ").append(labNames[i]).append(" Lab:\n");
                
                
                String resultStr = labResult.toString();
                if (resultStr.length() > 500) {
                    labResults.append("   ").append(resultStr.substring(0, 500)).append("...\n");
                } else {
                    labResults.append("   ").append(resultStr).append("\n");
                }
                labResults.append("\n");
            }
        }
        
        
        Object labErrors = request.getParameter("labErrors", Object.class);
        if (labErrors != null) {
            labResults.append("Lab 오류 정보:\n");
            labResults.append("   ").append(labErrors.toString()).append("\n\n");
        }
        
        if (!hasResults) {
            labResults.append("Lab 결과가 제공되지 않았습니다.\n");
        }
        
        
        String processingMode = request.getParameter("processingMode", String.class);
        String dataSource = request.getParameter("dataSource", String.class);
        String analysisType = request.getParameter("analysisType", String.class);
        
        labResults.append("처리 정보:\n");
        labResults.append("- 처리 모드: ").append(processingMode != null ? processingMode : "미제공").append("\n");
        labResults.append("- 데이터 소스: ").append(dataSource != null ? dataSource : "미제공").append("\n");
        labResults.append("- 분석 타입: ").append(analysisType != null ? analysisType : "미제공").append("\n");
        
        return labResults.toString();
    }

    
    private String extractAnalysisScope(AIRequest<? extends DomainContext> request) {
        String analysisScope = request.getParameter("analysisScope", String.class);
        
        if (analysisScope != null && !analysisScope.trim().isEmpty()) {
            return analysisScope;
        }
        
        
        if (request.getContext() instanceof SecurityCopilotContext) {
            SecurityCopilotContext context = (SecurityCopilotContext) request.getContext();
            return context.getAnalysisScope();
        }
        
        return "COMPREHENSIVE";
    }
    
    
    public BeanOutputConverter<SecurityCopilotResponse> getConverter() {
        return converter;
    }
} 