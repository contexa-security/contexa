package io.contexa.contexacore.autonomous.mcp;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.List;

public interface McpSecurityContextProvider {

    McpSecurityContext resolve(SecurityEvent event);

    record McpSecurityContext(List<ContextEntry> resources, List<ContextEntry> prompts) {

        public boolean hasEntries() {
            return resources != null && !resources.isEmpty()
                    || prompts != null && !prompts.isEmpty();
        }
    }

    record ContextEntry(String name, String description, String content) {
    }
}