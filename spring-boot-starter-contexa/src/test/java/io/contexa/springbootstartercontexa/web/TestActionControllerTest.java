package io.contexa.springbootstartercontexa.web;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.ZeroTrustAnalysisData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TestActionControllerTest {

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("분석 완료 상태는 reasoning과 requestId를 그대로 반환한다")
    void detail() {
        ZeroTrustActionRepository repository = mock(ZeroTrustActionRepository.class);
        TestActionController controller = new TestActionController(repository);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("alice", "pw"));

        when(repository.getAnalysisData("alice")).thenReturn(new ZeroTrustAnalysisData(
                ZeroTrustAction.BLOCK.name(),
                0.94,
                0.88,
                "device and IP mismatch",
                2,
                "2026-03-29T11:00:00Z",
                "takeover likely after auth",
                "takeover likely after auth",
                "STRICT",
                "req-777",
                "ctx-777",
                "BLOCK"
        ));

        ResponseEntity<Map<String, Object>> response = controller.getActionStatus(null);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody())
                .containsEntry("action", "BLOCK")
                .containsEntry("analysisStatus", "ANALYZED")
                .containsEntry("requestId", "req-777")
                .containsEntry("contextBindingHash", "ctx-777")
                .containsEntry("llmProposedAction", "BLOCK");
    }

    @Test
    @DisplayName("리셋은 현재 사용자의 저장 action을 비운다")
    void reset() {
        ZeroTrustActionRepository repository = mock(ZeroTrustActionRepository.class);
        TestActionController controller = new TestActionController(repository);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("alice", "pw"));

        ResponseEntity<Map<String, Object>> response = controller.resetAction(null);

        verify(repository).removeAllUserData("alice");
        assertThat(response.getBody()).containsEntry("currentAction", ZeroTrustAction.PENDING_ANALYSIS.name());
    }
}
