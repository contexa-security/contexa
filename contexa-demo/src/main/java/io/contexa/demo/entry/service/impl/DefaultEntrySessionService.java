package io.contexa.demo.entry.service.impl;

import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.entry.configuration.EntryProperties;
import io.contexa.demo.entry.dto.EntryLocation;
import io.contexa.demo.entry.dto.EntrySession;
import io.contexa.demo.entry.dto.PendingCode;
import io.contexa.demo.entry.repository.EntryReadRepository;
import io.contexa.demo.entry.service.EntrySessionService;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class DefaultEntrySessionService implements EntrySessionService {

    private final EntryReadRepository repository;
    private final EntryProperties properties;
    private final LabProperties lab;

    public DefaultEntrySessionService(EntryReadRepository repository, EntryProperties properties, LabProperties lab) {
        this.repository = repository;
        this.properties = properties;
        this.lab = lab;
    }

    public EntrySession inspect(String hash) {
        var visitor = repository.find(hash, false);
        var challenge = visitor == null || visitor.verified() ? null : repository.latestChallenge(visitor.id());
        PendingCode pending = challenge == null ? null : new PendingCode(challenge.id(), challenge.state(),
                challenge.expiresAt(), challenge.createdAt().plus(properties.resendInterval()));
        boolean configured =
                StringUtils.hasText(properties.mail().host()) && StringUtils.hasText(properties.mail().from());
        return new EntrySession(visitor == null ? "NOT_VERIFIED" : visitor.verified() ? "VERIFIED" : "PENDING",
                visitor != null && visitor.verified() ? visitor.id() : null,
                visitor == null ? null : visitor.expiresAt(), configured, pending);
    }

    public EntryLocation location() {
        return new EntryLocation(lab.role(), properties.portalUrl());
    }
}
