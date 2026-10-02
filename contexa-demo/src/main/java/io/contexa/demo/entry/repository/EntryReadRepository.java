package io.contexa.demo.entry.repository;

import io.contexa.demo.entry.domain.EmailChallenge;
import io.contexa.demo.entry.domain.Visitor;

import java.util.UUID;

public interface EntryReadRepository {

    Visitor find(String tokenHash, boolean lock);

    EmailChallenge challenge(UUID id);

    EmailChallenge latestChallenge(UUID visitorId);
}
