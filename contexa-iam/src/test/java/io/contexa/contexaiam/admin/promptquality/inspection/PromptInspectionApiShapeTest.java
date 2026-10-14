package io.contexa.contexaiam.admin.promptquality.inspection;

import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.GetMapping;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R1b-6: the inspection API has no job endpoints: a period's re-inspection is read by one count of the period, not by a
 * job id or a job list kept on one instance.
 */
class PromptInspectionApiShapeTest {

    @Test
    void theApiHasNoJobEndpoints() {
        assertThat(Arrays.stream(PromptInspectionApiController.class.getDeclaredMethods())
                .map(method -> method.getAnnotation(GetMapping.class)).filter(mapping -> mapping != null)
                .flatMap(mapping -> Arrays.stream(mapping.value())))
                .doesNotContain("/reinspections/{jobId}");
        assertThat(Arrays.stream(PromptInspectionApiController.class.getDeclaredMethods()).map(Method::getName))
                .doesNotContain("reinspections", "reinspectionProgress");
    }
}
