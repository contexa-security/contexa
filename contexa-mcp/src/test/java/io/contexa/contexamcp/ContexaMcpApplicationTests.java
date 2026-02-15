package io.contexa.contexamcp;

import io.contexa.contexamcp.tools.FileQuarantineTool;
import io.contexa.contexamcp.tools.ProcessKillTool;
import io.contexa.contexamcp.tools.ThreatIntelligenceTool;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ContexaMcpApplicationTests {

    @Test
    void moduleLoads() {
        assertDoesNotThrow(() -> Class.forName("io.contexa.contexamcp.ContexaMcpApplication"));
    }

    @Test
    void fileQuarantineNullActionReturnsFailure() {
        FileQuarantineTool tool = new FileQuarantineTool();
        FileQuarantineTool.Response response = tool.quarantineFile(
                null, "/tmp/test.exe", "test", false, false, false, false, false);
        assertFalse(response.isSuccess());
        assertNotNull(response.getMessage());
    }

    @Test
    void fileQuarantineEmptyActionReturnsFailure() {
        FileQuarantineTool tool = new FileQuarantineTool();
        FileQuarantineTool.Response response = tool.quarantineFile(
                "  ", "/tmp/test.exe", "test", false, false, false, false, false);
        assertFalse(response.isSuccess());
    }

    @Test
    void processKillRequiresProcessInfo() {
        ProcessKillTool tool = new ProcessKillTool();
        ProcessKillTool.Response response = tool.killProcess(
                null, null, null, false, false, false, null);
        assertFalse(response.isSuccess());
    }

    @Test
    void threatIntelligenceRequiresIndicator() {
        ThreatIntelligenceTool tool = new ThreatIntelligenceTool();
        ThreatIntelligenceTool.Response response = tool.queryThreatIntelligence(
                null, null, false, false, null);
        assertFalse(response.isSuccess());
        assertNotNull(response.getError());
    }

    @Test
    void responseObjectsHaveSimulatedFlag() {
        FileQuarantineTool.Response fqResponse = FileQuarantineTool.Response.builder()
                .success(true).message("test").build();
        assertTrue(fqResponse.isSimulated());

        ProcessKillTool.Response pkResponse = ProcessKillTool.Response.builder()
                .success(true).message("test").build();
        assertTrue(pkResponse.isSimulated());

        ThreatIntelligenceTool.Response tiResponse = ThreatIntelligenceTool.Response.builder()
                .success(true).message("test").build();
        assertTrue(tiResponse.isSimulated());
    }
}
