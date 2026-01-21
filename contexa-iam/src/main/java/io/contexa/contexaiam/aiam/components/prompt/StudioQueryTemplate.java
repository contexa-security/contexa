package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacore.std.components.prompt.PromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptTemplateConfig;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.protocol.response.StudioQueryResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;

@Slf4j
@PromptTemplateConfig(
        key = "studioQuery",
        aliases = {"studio_query", "authorization_studio_query", "iam_natural_query"},
        description = "Spring AI Structured Output Authorization Studio Query Template"
)
public class StudioQueryTemplate implements PromptTemplate {

    private final BeanOutputConverter<StudioQueryResponse> converter = 
        new BeanOutputConverter<>(StudioQueryResponse.class);

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return buildStudioQuerySystemPrompt(systemMetadata);
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        
        String naturalQuery = extractNaturalQuery(request);

        String iamDataContext = request.getParameter("iamDataContext", String.class);

        String actualContextInfo = iamDataContext != null ? iamDataContext : contextInfo;

        return buildStudioQueryUserPrompt(naturalQuery, actualContextInfo);
    }

    private String buildStudioQuerySystemPrompt(String systemMetadata) {
        return String.format("""
              <role>
              당신은 제공된 IAM 데이터와 사용자의 질문을 분석하여 답변하는 한국어 권한 분석 전문가입니다.
              </role>

              <instructions>
              1. **질의 분석**: 질의를 정확히 해석하여 요구사항을 파악하세요.
                 - "누가 ~할 수 있나요" = 해당 권한을 보유한 사용자만 반환
                 - "누가 ~할 수 없나요" = 해당 권한이 없는 사용자만 반환
                 - "모든 사용자" = 전체 사용자 분석
              
              2. **데이터 필터링**: 질의에 정확히 부합하는 데이터만 선별하세요.
                 - 질의와 관련된 사용자만 analysisResults에 포함
                 - 질의와 무관한 사용자는 완전히 제외
                 - 권한 유무가 핵심인 경우 해당 권한 여부로만 판단
              
              3. **JSON 출력**: `===JSON시작===` 마커와 함께 필터링된 결과만 출력하세요.
                 - analysisResults: 질의에 부합하는 사용자만
                 - 제공된 **[데이터]**에 있는 실제 값만 사용
              </instructions>
            
            <output_format>
            ===JSON시작===
            {
              "naturalLanguageAnswer": "질의에 대한 명확한 한국어 답변 (질의와 부합하는 사용자만 언급)",
              "analysisResults": [
                {
                  "userName": "질의에 부합하는 실제 사용자명만",
                  "groupName": "해당 사용자의 실제 그룹명",
                  "roleName": "해당 사용자의 실제 역할명", 
                  "permissionName": "질의와 관련된 실제 권한명",
                  "hasPermission": true,
                  "description": "해당 사용자의 실제 권한 상황 설명"
                }
              ],
              "visualizationData": {
                "nodes": [
                  {"id": "실제ID", "type": "USER|GROUP|PERMISSION", "label": "실제라벨", "properties": {"name": "실제이름"}},
                  "
                ],
                "edges": [
                  {"source": "실제소스ID", "target": "실제타겟ID", "type": "HAS_ROLE|HAS_PERMISSION", "properties": {"permissions": ["실제권한명"]}},
                  "// 주의: 질의와 관련된 연결 관계만 포함"
                ]
              },
              "queryResults": [
                {
                  "entity": "분석 대상 엔티티명",
                  "actionType": "수행 가능한 액션",
                  "description": "분석 결과 설명",
                  "relevanceScore": 95
                }
              ],
              "recommendations": [
                {
                  "title": "실제 분석 결과 기반 권장사항",
                  "description": "분석 결과를 바탕으로 한 구체적 설명",
                  "priority": 1,
                  "type": "권장사항 유형",
                  "actionItems": [
                    "구체적이고 실행 가능한 항목들"
                  ],
                  "actionLinks": [
                    {
                      "text": "실행 가능한 액션 텍스트",
                      "url": "/admin/실제-페이지-경로",
                      "type": "PRIMARY"
                    }
                  ]
                }
              ]
            }
                ===JSON끝===
           </output_format>
            """, systemMetadata);
    }

    /**
     * 한국어 전용 사용자 프롬프트
     */
    private String buildStudioQueryUserPrompt(String naturalQuery, String contextInfo) {
        // 디버깅: 사용자 프롬프트에 전달되는 데이터 확인
        log.info("사용자 프롬프트 - 질의: {}", naturalQuery);
        log.info("사용자 프롬프트 - contextInfo 길이: {}", contextInfo != null ? contextInfo.length() : 0);
        if (contextInfo != null && contextInfo.length() > 0) {
            log.info("사용자 프롬프트 - contextInfo 첫 300자: {}",
                    contextInfo.length() > 300 ? contextInfo.substring(0, 300) + "..." : contextInfo);
        }

        String userPrompt = String.format("""
              [질의]
              %s

              [데이터]
              %s
              
              Generate complete StudioQueryResponse in JSON format.
            """, naturalQuery, contextInfo);
        
        // BeanOutputConverter의 포맷 지시사항을 다시 추가 (강조)
        return userPrompt + "\n\n" + converter.getFormat();
    }

    /**
     * 요청에서 자연어 질의 추출
     */
    private String extractNaturalQuery(AIRequest<? extends DomainContext> request) {
        // 디버깅: 전체 파라미터 확인
        log.info("StudioQueryTemplate - 전체 파라미터 키: {}", request.getParameters().keySet());

        // StudioQueryRequest 에서 자연어 질의 추출
        String naturalQuery = request.getParameter("naturalLanguageQuery", String.class);

        // 디버깅: iamDataContext 파라미터 확인
        String iamDataContext = request.getParameter("iamDataContext", String.class);
        log.info("StudioQueryTemplate - iamDataContext 존재 여부: {}", iamDataContext != null);
        if (iamDataContext != null) {
            log.info("StudioQueryTemplate - iamDataContext 길이: {}", iamDataContext.length());
            log.info("StudioQueryTemplate - iamDataContext 첫 200자: {}",
                    iamDataContext.length() > 200 ? iamDataContext.substring(0, 200) + "..." : iamDataContext);
        }

        if (naturalQuery != null) {
            return naturalQuery;
        }

        // 컨텍스트에서 추출 시도
        if (request.getContext() instanceof StudioQueryContext context) {
            // StudioQueryContext에서 질의 정보 추출 (향후 구현)
            return "Authorization Studio 질의";
        }

        return "자연어 질의가 제공되지 않았습니다";
    }

    public BeanOutputConverter<StudioQueryResponse> getConverter() {
        return converter;
    }
} 