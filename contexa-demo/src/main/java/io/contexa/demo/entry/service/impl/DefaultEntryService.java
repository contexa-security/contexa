package io.contexa.demo.entry.service.impl;

import io.contexa.demo.entry.configuration.EntryProperties;
import io.contexa.demo.entry.domain.EmailChallenge;
import io.contexa.demo.entry.dto.DeliveryPreparation;
import io.contexa.demo.entry.dto.EntryResult;
import io.contexa.demo.entry.mail.EntryMailGateway;
import io.contexa.demo.entry.repository.EntryRepository;
import io.contexa.demo.entry.service.EntryService;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

@Service
@Profile("portal")
public class DefaultEntryService implements EntryService {

    private final EntryRepository store;
    private final EntryProperties properties;
    private final EntryMailGateway mail;
    private final PasswordEncoder encoder;
    private final SecureRandom random = new SecureRandom();

    public DefaultEntryService(EntryRepository store, EntryProperties properties, EntryMailGateway mail,
            PasswordEncoder encoder) {
        this.store = store;
        this.properties = properties;
        this.mail = mail;
        this.encoder = encoder;
    }

    public EntryResult request(String tokenHash, UUID requestId, String address, String ip, String language) {
        String email = address.trim().toLowerCase(Locale.ROOT);
        String code = String.format(Locale.ROOT, "%06d", random.nextInt(1_000_000));
        String codeHash = encoder.encode(code);
        DeliveryPreparation preparation = store.transaction(tx -> {
            tx.lockRequest(requestId);
            Instant now = Instant.now();
            var visitor = tx.find(tokenHash, true);
            if (visitor == null) {
                visitor = tx.create(tokenHash, now.plus(properties.pendingLifetime()));
            }
            if (visitor.verified()) {
                return new DeliveryPreparation(
                        new EntryResult(409, "ALREADY_VERIFIED", null, visitor.expiresAt(), null), false);
            }
            var existing = tx.challenge(requestId);
            if (existing != null) {
                if (!existing.visitorId().equals(visitor.id()) || !existing.email().equals(email)) {
                    return new DeliveryPreparation(new EntryResult(409, "REQUEST_CONFLICT", null, null, null), false);
                }
                return new DeliveryPreparation(response(existing), false);
            }
            Instant previous = tx.latestRequest(visitor.id());
            if (previous != null && previous.plus(properties.resendInterval()).isAfter(now)) {
                return new DeliveryPreparation(
                        new EntryResult(429, "RESEND_TOO_SOON", null, null, previous.plus(properties.resendInterval())),
                        false);
            }
            tx.lockRateKeys(email, ip);
            if (tx.quotaExceeded(email, ip, properties)) {
                return new DeliveryPreparation(new EntryResult(429, "DAILY_LIMIT", null, null, null), false);
            }
            Instant expiresAt = now.plus(properties.codeLifetime());
            if (expiresAt.isAfter(visitor.expiresAt())) {
                expiresAt = visitor.expiresAt();
            }
            tx.insertChallenge(requestId, visitor, email, codeHash, ip, expiresAt);
            return new DeliveryPreparation(new EntryResult(202, "SENDING", requestId, expiresAt, null), true);
        });
        if (!preparation.send()) {
            return preparation.result();
        }
        boolean sent = false;
        try {
            mail.send(email, code, language);
            sent = true;
        } catch (RuntimeException unavailable) {
            // No OTP, mail body, recipient or transport credentials enter logs.
        }
        store.delivered(requestId, sent);
        return response(store.challenge(requestId));
    }

    private EntryResult response(EmailChallenge challenge) {
        String state = challenge.state();
        if ("SENT".equals(state) && !challenge.expiresAt().isAfter(Instant.now())) {
            state = "EXPIRED";
        }
        int status = switch (state) {
            case "SENT" -> 200;
            case "SENDING" -> 202;
            case "FAILED" -> 503;
            default -> 409;
        };
        return new EntryResult(status, state, challenge.id(), challenge.expiresAt(),
                challenge.createdAt().plus(properties.resendInterval()));
    }

    public EntryResult verify(String tokenHash, UUID requestId, String code, String newHash) {
        return store.transaction(tx -> {
            var visitor = tx.find(tokenHash, true);
            if (visitor == null || visitor.verified()) {
                return new EntryResult(401, "ENTRY_SESSION_INVALID", null, null, null);
            }
            var challenge = tx.challenge(requestId);
            if (challenge == null || !challenge.visitorId().equals(visitor.id())) {
                return new EntryResult(400, "REQUEST_INVALID", null, null, null);
            }
            if (!"SENT".equals(challenge.state())) {
                return new EntryResult(409, challenge.state(), requestId, challenge.expiresAt(), null);
            }
            if (!challenge.expiresAt().isAfter(Instant.now())) {
                tx.reject(challenge, "EXPIRED");
                return new EntryResult(410, "EXPIRED", requestId, challenge.expiresAt(), null);
            }
            if (challenge.attempts() >= properties.maxAttempts()) {
                tx.reject(challenge, "LOCKED");
                return new EntryResult(429, "LOCKED", requestId, challenge.expiresAt(), null);
            }
            if (!encoder.matches(code, challenge.codeHash())) {
                tx.incorrect(challenge, properties.maxAttempts());
                boolean locked = challenge.attempts() + 1 >= properties.maxAttempts();
                return new EntryResult(locked ? 429 : 400, locked ? "LOCKED" : "CODE_INCORRECT", requestId,
                        challenge.expiresAt(), null);
            }
            Instant expiry = Instant.now().plus(properties.verifiedLifetime());
            tx.consume(challenge, newHash, expiry);
            return new EntryResult(200, "VERIFIED", requestId, expiry, null);
        });
    }
}
