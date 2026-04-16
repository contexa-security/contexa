package io.contexa.autoconfigure.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "contexa.llm.selection")
public class ContexaLlmSelectionProperties {

    private Chat chat = new Chat();
    private Embedding embedding = new Embedding();

    public enum Mode {
        DYNAMIC_PRIORITY,
        SPRING_PRIMARY
    }

    @Data
    public static class Chat {
        private Mode mode = Mode.DYNAMIC_PRIORITY;
        private String priority = "";
    }

    @Data
    public static class Embedding {
        private Mode mode = Mode.DYNAMIC_PRIORITY;
        private String priority = "";
    }
}