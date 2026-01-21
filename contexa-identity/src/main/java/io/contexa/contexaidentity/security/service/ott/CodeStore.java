package io.contexa.contexaidentity.security.service.ott;

import org.springframework.security.authentication.ott.OneTimeToken;

import java.time.Duration;

public interface CodeStore {
    
    void save(String code, OneTimeToken token, Duration duration);

    OneTimeToken consume(String code);
}
