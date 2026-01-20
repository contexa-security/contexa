package io.contexa.contexacoreenterprise.mcp.tool.resolution;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.util.Map;


@Slf4j
@RequiredArgsConstructor
public class SpringBeanToolCallbackResolver implements ToolCallbackResolver {
    
    private final ApplicationContext applicationContext;
    
    @Override
    public ToolCallback resolve(String toolName) {

        log.trace("Spring Bean 도구 검색: {}", toolName);
        
        try {
            
            Map<String, ToolCallback> toolBeans = 
                applicationContext.getBeansOfType(ToolCallback.class);
            
            
            for (Map.Entry<String, ToolCallback> entry : toolBeans.entrySet()) {
                ToolCallback tool = entry.getValue();
                if (tool.getToolDefinition().name().equals(toolName)) {
                    log.debug("Spring Bean 도구 발견: {} (bean: {})", 
                        toolName, entry.getKey());
                    return tool;
                }
            }
            
            
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
    
    
    public int getToolCount() {
        return applicationContext.getBeansOfType(ToolCallback.class).size();
    }
    
    
    public String[] getToolNames() {
        return applicationContext.getBeansOfType(ToolCallback.class).values()
            .stream()
            .map(tool -> tool.getToolDefinition().name())
            .toArray(String[]::new);
    }
    
    
    public Map<String, ToolCallback> getAllTools() {
        return applicationContext.getBeansOfType(ToolCallback.class);
    }
}