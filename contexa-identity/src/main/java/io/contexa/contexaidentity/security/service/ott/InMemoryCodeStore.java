package io.contexa.contexaidentity.security.service.ott;

import org.springframework.security.authentication.ott.OneTimeToken;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class InMemoryCodeStore implements CodeStore {

    private final ConcurrentMap<String, OneTimeToken> store = new ConcurrentHashMap<>();

    @Override
    public void save(String code, OneTimeToken token, Duration duration) {
        store.put(code, token);
    }

    @Override
    public OneTimeToken consume(String code) {
        return store.remove(code);
    }
}
