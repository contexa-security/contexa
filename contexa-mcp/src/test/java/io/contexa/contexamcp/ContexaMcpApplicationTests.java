package io.contexa.contexamcp;

import io.contexa.contexamcp.adapter.NoOpThreatIntelligenceAdapter;
import io.contexa.contexamcp.tools.ThreatIntelligenceTool;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ContexaMcpApplicationTests {

    @Test
    void moduleLoads() {
        assertDoesNotThrow(() -> Class.forName("io.contexa.contexamcp.ContexaMcpApplication"));
    }

    @Test
    void threatIntelligenceRequiresIndicator() {
        ThreatIntelligenceTool tool = new ThreatIntelligenceTool(new NoOpThreatIntelligenceAdapter());
        ThreatIntelligenceTool.Response response = tool.queryThreatIntelligence(
                null, null);
        assertFalse(response.isSuccess());
        assertNotNull(response.getError());
    }

    @Test
    void threatIntelligenceNoOpAdapterReturnsNoResults() {
        ThreatIntelligenceTool tool = new ThreatIntelligenceTool(new NoOpThreatIntelligenceAdapter());
        ThreatIntelligenceTool.Response response = tool.queryThreatIntelligence(
                "192.168.1.1", "ip");
        assertTrue(response.isSuccess());
        assertNull(response.getIntelligence());
        assertFalse(response.isExternalProviderUsed());
        assertEquals("NoOp", response.getProviderName());
    }
}
