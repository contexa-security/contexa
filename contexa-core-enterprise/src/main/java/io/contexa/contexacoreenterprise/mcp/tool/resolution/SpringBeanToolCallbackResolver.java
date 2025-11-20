package io.contexa.contexacoreenterprise.mcp.tool.resolution;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * SpringBeanToolCallbackResolver
 * 
 * Spring ApplicationContext 에서 ToolCallback 빈을 검색합니다.
 * Spring AI 표준 Resolver 구현입니다.
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class SpringBeanToolCallbackResolver implements ToolCallbackResolver {
    
    private final ApplicationContext applicationContext;
    
    @Override
    public ToolCallback resolve(String toolName) {

        log.trace("Spring Bean 도구 검색: {}", toolName);
        
        try {
            // ApplicationContext 에서 모든 ToolCallback 빈 검색
            Map<String, ToolCallback> toolBeans = 
                applicationContext.getBeansOfType(ToolCallback.class);
            
            // 이름으로 매칭
            for (Map.Entry<String, ToolCallback> entry : toolBeans.entrySet()) {
                ToolCallback tool = entry.getValue();
                if (tool.getToolDefinition().name().equals(toolName)) {
                    log.debug("Spring Bean 도구 발견: {} (bean: {})", 
                        toolName, entry.getKey());
                    return tool;
                }
            }
            
            // Bean 이름으로도 검색 시도
            if (applicationContext.containsBean(toolName)) {
                Object bean = applicationContext.getBean(toolName);
                if (bean instanceof ToolCallback) {
                    log.debug("Spring Bean 도구 발견 (bean name): {}", toolName);
                    return (ToolCallback) bean;
                }
            }
            
        } catch (Exception e) {
            log.warn("Spring Bean 도구 검색 중 오류: {} - {}", toolName, e.getMessage());
        }
        
        return null;
    }
    
    /**
     * 등록된 도구 개수 반환
     */
    public int getToolCount() {
        return applicationContext.getBeansOfType(ToolCallback.class).size();
    }
    
    /**
     * 모든 도구 이름 반환
     */
    public String[] getToolNames() {
        return applicationContext.getBeansOfType(ToolCallback.class).values()
            .stream()
            .map(tool -> tool.getToolDefinition().name())
            .toArray(String[]::new);
    }
    
    /**
     * 모든 도구 반환
     */
    public Map<String, ToolCallback> getAllTools() {
        return applicationContext.getBeansOfType(ToolCallback.class);
    }
}