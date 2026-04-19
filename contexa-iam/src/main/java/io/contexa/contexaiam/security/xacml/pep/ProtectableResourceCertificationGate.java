package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexacommon.annotation.Protectable;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.core.Authentication;

public interface ProtectableResourceCertificationGate {

    CertificationDecision evaluate(
            MethodInvocation methodInvocation,
            Authentication authentication,
            Protectable protectable,
            String resourceId
    );

    record CertificationDecision(
            boolean allowed,
            String state,
            String message
    ) {

        public static CertificationDecision allowed(String message) {
            return new CertificationDecision(true, "ZERO_TRUST_ALLOWED", message);
        }

        public static CertificationDecision blocked(String state, String message) {
            return new CertificationDecision(false, state, message);
        }
    }
}
