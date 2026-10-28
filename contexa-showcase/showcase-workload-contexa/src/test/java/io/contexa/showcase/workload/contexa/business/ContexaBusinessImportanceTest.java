package io.contexa.showcase.workload.contexa.business;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.annotation.ResourceImportance;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent RL-14: the business application states the importance of every resource it protects, on the resource
 * itself. A list of a project's documents is non-sensitive (a request for a confidential project raises it); a single
 * document is left unspecified because its sensitivity depends on the document; everything that carries data out, changes
 * access or holds customer records is sensitive.
 */
class ContexaBusinessImportanceTest {

    private static ResourceImportance importanceOf(String method) {
        for (Method candidate : ContexaBusinessOperations.class.getMethods()) {
            if (candidate.getName().equals(method) && candidate.getDeclaringClass() == ContexaBusinessOperations.class) {
                Protectable protectable = candidate.getAnnotation(Protectable.class);
                assertThat(protectable).as(method).isNotNull();
                return protectable.importance();
            }
        }
        throw new AssertionError("No such protected method: " + method);
    }

    @Test
    void everyProtectedMethodStatesItsImportance() {
        Map<String, ResourceImportance> expected = Map.of(
                "listDocuments", ResourceImportance.NON_SENSITIVE,
                "readDocument", ResourceImportance.UNSPECIFIED,
                "downloadDocument", ResourceImportance.SENSITIVE,
                "deleteDocument", ResourceImportance.SENSITIVE,
                "exportDocuments", ResourceImportance.SENSITIVE,
                "openExportStream", ResourceImportance.SENSITIVE,
                "exportDocumentsAsync", ResourceImportance.SENSITIVE,
                "readCustomer", ResourceImportance.SENSITIVE,
                "grantRole", ResourceImportance.SENSITIVE);

        expected.forEach((method, importance) -> assertThat(importanceOf(method)).as(method).isEqualTo(importance));
    }

    @Test
    void noMethodThatCarriesDataOutOrChangesAccessIsLeftUnspecifiedOrNonSensitive() {
        for (Method method : ContexaBusinessOperations.class.getMethods()) {
            Protectable protectable = method.getAnnotation(Protectable.class);
            if (protectable == null) {
                continue;
            }
            boolean carriesOutOrChanges = protectable.exportSensitive() || protectable.privileged()
                    || protectable.actions().length == 1 && java.util.Set.of("EXPORT", "DELETE", "DOWNLOAD", "ADMIN")
                    .contains(protectable.actions()[0]);
            if (carriesOutOrChanges) {
                assertThat(protectable.importance()).as(method.getName()).isEqualTo(ResourceImportance.SENSITIVE);
            }
        }
    }
}
