package io.contexa.autoconfigure.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
@ConfigurationProperties(prefix = "contexa.llm.bindings")
public class ContexaLlmBindingProperties {

    private Map<String, Binding> chat = new LinkedHashMap<>();
    private Map<String, Binding> embedding = new LinkedHashMap<>();

    @Data
    public static class Binding {
        private String beanName = "";
        private String provider = "";
        private String modelId = "";
        private List<String> aliases = new ArrayList<>();
        private boolean enabled = true;
        private boolean primary = false;
    }
}