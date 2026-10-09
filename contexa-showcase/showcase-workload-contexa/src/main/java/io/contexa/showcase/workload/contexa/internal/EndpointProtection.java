package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.showcase.business.work.RbacPolicy;
import io.contexa.showcase.workload.contexa.business.ContexaBusinessOperations;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.TreeMap;

/**
 * How each business endpoint of control D is protected, read from the {@code @Protectable} declarations themselves
 * so the execution specification can never disagree with the code (deck p.25: name the protection per endpoint).
 */
public final class EndpointProtection {

    private static final Map<String, String> METHOD_OF_OPERATION = Map.of(
            "PROJECT_LIST", "listProjects",
            "DOCUMENT_READ", "readDocument",
            "DOCUMENT_DOWNLOAD", "downloadDocument",
            "EXPORT", "exportDocuments",
            "EXPORT_STREAM", "openExportStream",
            "EXPORT_ASYNC", "exportDocumentsAsync",
            "CUSTOMER_READ", "readCustomer",
            "ROLE_GRANT", "grantRole");

    private EndpointProtection() {
    }

    /** {@code "GET /api/documents/*" -> "async"}, {@code "sync"} or {@code "none"}. */
    public static Map<String, String> describe() {
        Map<String, String> protection = new TreeMap<>();
        for (RbacPolicy.Rule rule : RbacPolicy.RULES) {
            String methodName = METHOD_OF_OPERATION.get(rule.operation().name());
            protection.put(rule.method() + " " + rule.pattern(), mode(methodName));
        }
        return protection;
    }

    private static String mode(String methodName) {
        for (Method method : ContexaBusinessOperations.class.getDeclaredMethods()) {
            if (method.getName().equals(methodName)) {
                Protectable protectable = method.getAnnotation(Protectable.class);
                if (protectable == null) {
                    return "none";
                }
                return protectable.sync() ? "sync" : "async";
            }
        }
        return "none";
    }
}
