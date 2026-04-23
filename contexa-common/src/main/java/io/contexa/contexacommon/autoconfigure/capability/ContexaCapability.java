package io.contexa.contexacommon.autoconfigure.capability;

import java.util.Locale;

public enum ContexaCapability {
    LLM_RUNTIME,
    EMBEDDING_RUNTIME,
    RAG_VECTOR,
    SECURITY_LEARNING,
    AUTONOMOUS_DECISION,
    BRIDGE,
    PQA_ENGINE,
    ENTERPRISE_SOAR,
    ENTERPRISE_MCP,
    ENTERPRISE_DASHBOARD;

    public String propertyKey() {
        return name().toLowerCase(Locale.ROOT).replace('_', '-');
    }
}
