package io.contexa.demo.entry.repository;

import io.contexa.demo.entry.configuration.EntryProperties;
import io.contexa.demo.entry.domain.EmailChallenge;
import io.contexa.demo.entry.domain.Visitor;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

public interface EntryRepository extends EntryReadRepository {

    <T> T transaction(Function<EntryRepository, T> work);

    Visitor create(String tokenHash, Instant expiry);

    void lockRequest(UUID requestId);

    void lockRateKeys(String email, String ip);

    boolean quotaExceeded(String email, String ip, EntryProperties limits);

    Instant latestRequest(UUID visitorId);

    void insertChallenge(UUID id, Visitor visitor, String email, String codeHash, String ip, Instant expiry);

    void delivered(UUID id, boolean sent);

    void reject(EmailChallenge challenge, String state);

    void incorrect(EmailChallenge challenge, int maxAttempts);

    void consume(EmailChallenge challenge, String newHash, Instant expiresAt);
}
