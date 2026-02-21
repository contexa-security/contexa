package io.contexa.contexacoreenterprise.mcp.tool.resolution;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class FallbackToolResolver implements ToolCallbackResolver {
    
    private final Map<String, ToolCallback> fallbackTools = new ConcurrentHashMap<>();
    
    public FallbackToolResolver() {
        initializeFallbackTools();
    }
    
    @Override
    public ToolCallback resolve(String toolName) {

        ToolCallback specificFallback = fallbackTools.get(toolName);
        if (specificFallback != null) {
                        return specificFallback;
        }

        ToolCallback patternFallback = findPatternMatchedFallback(toolName);
        if (patternFallback != null) {
                        return patternFallback;
        }

        log.error("No fallback tool found for: {}", toolName);
        return null;
    }

    private void initializeFallbackTools() {
        
        fallbackTools.put("network_scan_fallback", new FallbackToolCallback(
            "network_scan_fallback",
            "Network scan tool is unavailable",
            "Network scan feature is currently disabled. Please contact the administrator."
        ));

        fallbackTools.put("log_analysis_fallback", new FallbackToolCallback(
            "log_analysis_fallback",
            "Log analysis tool is unavailable",
            "Log analysis service is temporarily suspended. Please try again later."
        ));
        
            }

    private ToolCallback findPatternMatchedFallback(String toolName) {
        
        if (toolName.contains("scan") || toolName.contains("security")) {
            return new FallbackToolCallback(
                toolName + "_fallback",
                "Security tool unavailable",
                String.format("Security tool '%s' is currently unavailable. Please check the security policy.", toolName)
            );
        }

        if (toolName.contains("ai") || toolName.contains("llm")) {
            return new FallbackToolCallback(
                toolName + "_fallback",
                "AI tool unavailable",
                String.format("AI tool '%s' is currently offline. Please check the API key.", toolName)
            );
        }
        
        return null;
    }

    public void registerFallback(String toolName, ToolCallback fallback) {
        fallbackTools.put(toolName, fallback);
            }

    public void removeFallback(String toolName) {
        fallbackTools.remove(toolName);
            }

    public Map<String, Object> getStatistics() {
        return Map.of(
            "totalFallbacks", fallbackTools.size(),
            "fallbackNames", fallbackTools.keySet()
        );
    }

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
            log.error("Fallback tool invoked: {} with args: {}", name, arguments);
            return fallbackMessage;
        }
    }
}
