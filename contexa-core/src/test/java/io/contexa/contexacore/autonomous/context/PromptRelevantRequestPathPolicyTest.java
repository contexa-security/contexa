package io.contexa.contexacore.autonomous.context;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PromptRelevantRequestPathPolicyTest {

    @Test
    @DisplayName("테스트 화면과 MFA 보조 경로는 신규성 판단을 소모하는 prompt-relevant 경로가 아니어야 한다")
    void shouldTreatTestAndMfaPathsAsNoise() {
        assertThat(PromptRelevantRequestPathPolicy.isPromptRelevantPath("/admin/test/security")).isFalse();
        assertThat(PromptRelevantRequestPathPolicy.isPromptRelevantPath("/customLogin")).isFalse();
        assertThat(PromptRelevantRequestPathPolicy.isPromptRelevantPath("/admin/mfa/login")).isFalse();
        assertThat(PromptRelevantRequestPathPolicy.isPromptRelevantPath("/admin/login/mfa-ott")).isFalse();
    }

    @Test
    @DisplayName("보호 리소스 경로는 prompt-relevant 경로로 유지되어야 한다")
    void shouldKeepProtectedResourcePathsRelevant() {
        assertThat(PromptRelevantRequestPathPolicy.isPromptRelevantPath("/admin/api/security-test/sensitive/resource-001")).isTrue();
        assertThat(PromptRelevantRequestPathPolicy.isPromptRelevantPath("/admin/api/security-test/critical/resource-001")).isTrue();
    }
}
