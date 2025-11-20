package io.contexa.contexacoreenterprise.mcp.tool.resolution;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * FallbackToolResolver
 * 
 * 다른 Resolver가 도구를 찾지 못했을 때 대체 도구를 제공합니다.
 * 기본 동작이나 에러 메시지를 반환하는 도구들을 관리합니다.
 */
@Component
@Slf4j
public class FallbackToolResolver implements ToolCallbackResolver {
    
    private final Map<String, ToolCallback> fallbackTools = new ConcurrentHashMap<>();
    
    public FallbackToolResolver() {
        initializeFallbackTools();
    }
    
    @Override
    public ToolCallback resolve(String toolName) {

        log.trace("Fallback 도구 검색: {}", toolName);
        
        // 특정 도구에 대한 대체 도구가 있는지 확인
        ToolCallback specificFallback = fallbackTools.get(toolName);
        if (specificFallback != null) {
            log.debug("특정 Fallback 도구 발견: {}", toolName);
            return specificFallback;
        }
        
        // 패턴 매칭을 통한 대체 도구 검색
        ToolCallback patternFallback = findPatternMatchedFallback(toolName);
        if (patternFallback != null) {
            log.debug("패턴 매칭 Fallback 도구 발견: {}", toolName);
            return patternFallback;
        }
        
        // 기본 대체 도구 반환
        log.debug("기본 Fallback 도구 반환: {}", toolName);
        return createDefaultFallback(toolName);
    }
    
    /**
     * 기본 대체 도구들 초기화
     */
    private void initializeFallbackTools() {
        // 네트워크 관련 도구 대체
        fallbackTools.put("network_scan_fallback", new FallbackToolCallback(
            "network_scan_fallback",
            "네트워크 스캔 도구를 사용할 수 없습니다",
            "네트워크 스캔 기능이 현재 비활성화되어 있습니다. 관리자에게 문의하세요."
        ));
        
        // 로그 분석 도구 대체
        fallbackTools.put("log_analysis_fallback", new FallbackToolCallback(
            "log_analysis_fallback",
            "로그 분석 도구를 사용할 수 없습니다",
            "로그 분석 서비스가 일시적으로 중단되었습니다. 잠시 후 다시 시도하세요."
        ));
        
        log.info("Fallback 도구 초기화 완료: {} 개", fallbackTools.size());
    }
    
    /**
     * 패턴 매칭을 통한 대체 도구 검색
     */
    private ToolCallback findPatternMatchedFallback(String toolName) {
        // 보안 관련 도구
        if (toolName.contains("scan") || toolName.contains("security")) {
            return new FallbackToolCallback(
                toolName + "_fallback",
                "보안 도구 사용 불가",
                String.format("보안 도구 '%s'를 현재 사용할 수 없습니다. 보안 정책을 확인하세요.", toolName)
            );
        }
        
        // AI 관련 도구
        if (toolName.contains("ai") || toolName.contains("llm")) {
            return new FallbackToolCallback(
                toolName + "_fallback",
                "AI 도구 사용 불가",
                String.format("AI 도구 '%s'가 현재 오프라인입니다. API 키를 확인하세요.", toolName)
            );
        }
        
        return null;
    }
    
    /**
     * 기본 대체 도구 생성
     */
    private ToolCallback createDefaultFallback(String toolName) {
        return new FallbackToolCallback(
            toolName + "_default_fallback",
            "도구를 찾을 수 없음",
            String.format("요청한 도구 '%s'를 찾을 수 없습니다. 도구 이름을 확인하거나 관리자에게 문의하세요.", toolName)
        );
    }
    
    /**
     * 대체 도구 등록
     */
    public void registerFallback(String toolName, ToolCallback fallback) {
        fallbackTools.put(toolName, fallback);
        log.info("Fallback 도구 등록: {}", toolName);
    }
    
    /**
     * 대체 도구 제거
     */
    public void removeFallback(String toolName) {
        fallbackTools.remove(toolName);
        log.info("Fallback 도구 제거: {}", toolName);
    }
    
    /**
     * 통계 정보
     */
    public Map<String, Object> getStatistics() {
        return Map.of(
            "totalFallbacks", fallbackTools.size(),
            "fallbackNames", fallbackTools.keySet()
        );
    }
    
    /**
     * 기본 Fallback 도구 구현
     */
    private static class FallbackToolCallback implements ToolCallback {
        private final String name;
        private final String description;
        private final String fallbackMessage;
        
        public FallbackToolCallback(String name, String description, String fallbackMessage) {
            this.name = name;
            this.description = description;
            this.fallbackMessage = fallbackMessage;
        }
        
        @Override
        public ToolDefinition getToolDefinition() {
            return ToolDefinition.builder()
                .name(name)
                .description(description)
                .inputSchema("{\"type\": \"object\", \"properties\": {}}")
                .build();
        }
        
        @Override
        public String call(String arguments) {
            log.warn("Fallback 도구 호출됨: {} with args: {}", name, arguments);
            return fallbackMessage;
        }
    }
}