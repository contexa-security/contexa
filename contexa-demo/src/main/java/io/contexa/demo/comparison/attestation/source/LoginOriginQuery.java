package io.contexa.demo.comparison.attestation.source;

import io.contexa.demo.comparison.attestation.dto.LoginOrigin;

public interface LoginOriginQuery {

    LoginOrigin find(String sessionSha256, String username);
}
