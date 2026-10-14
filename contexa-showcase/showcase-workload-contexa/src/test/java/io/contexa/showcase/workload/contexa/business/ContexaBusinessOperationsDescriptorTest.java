package io.contexa.showcase.workload.contexa.business;

import io.contexa.contexacommon.annotation.Protectable;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.TreeMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Control D declares on each protected method what the engine compares its requests by (P2-CHANGE-11 ④, after the v20
 * dictionary): the business category, the action family, and whether it is privileged or exports sensitive data. The
 * sensitivity is not declared, since the business application sets it on every request and a request value wins.
 */
class ContexaBusinessOperationsDescriptorTest {

    @Test
    void everyProtectedMethodDeclaresWhatTheEngineComparesItsRequestsBy() {
        Map<String, String> declared = new TreeMap<>();
        for (Method method : ContexaBusinessOperations.class.getDeclaredMethods()) {
            Protectable protectable = method.getAnnotation(Protectable.class);
            if (protectable != null) {
                declared.put(method.getName(), protectable.category() + " " + String.join(",", protectable.actions())
                        + (protectable.privileged() ? " privileged" : "")
                        + (protectable.exportSensitive() ? " exportSensitive" : "")
                        + (protectable.sync() ? " sync" : "")
                        + (protectable.sensitivity().isEmpty() ? "" : " sensitivity"));
            }
        }

        assertThat(declared).containsExactlyInAnyOrderEntriesOf(Map.of(
                "readDocument", "PROJECT_DOCUMENTS READ",
                "downloadDocument", "PROJECT_DOCUMENTS READ",
                "exportDocuments", "PROJECT_DOCUMENTS EXPORT exportSensitive sync",
                "openExportStream", "PROJECT_DOCUMENTS EXPORT exportSensitive",
                "exportDocumentsAsync", "PROJECT_DOCUMENTS EXPORT exportSensitive",
                "readCustomer", "CUSTOMER_RECORDS READ",
                "grantRole", "PROJECT_ACCESS ADMIN privileged sync"));
    }
}
