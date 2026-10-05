package io.contexa.showcase.workload.contexa.inbox;

import io.contexa.contexaidentity.security.service.ott.EmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Demo inbox that replaces outbound mail for the run principals. The engine still generates, stores and
 * verifies the one-time code; only delivery changes, so the visitor can read the code on screen.
 * <p>
 * Each recipient keeps only its latest code. Taking a code removes it, and a principal's cleanup discards it.
 */
public class DemoInboxEmailService extends EmailService {

    private static final Logger log = LoggerFactory.getLogger(DemoInboxEmailService.class);

    /** The engine renders the code inside the first strong element of its HTML message. */
    private static final Pattern CODE = Pattern.compile("<strong[^>]*>([^<]+)</strong>");

    private final Clock clock;
    private final Map<String, InboxCode> latestCodes = new ConcurrentHashMap<>();

    public DemoInboxEmailService(Clock clock) {
        super(null);
        this.clock = clock;
    }

    @Override
    public boolean isMailSenderConfigured() {
        return true;
    }

    @Override
    public void sendHtmlMessage(String to, String subject, String htmlBody) {
        Matcher matcher = CODE.matcher(htmlBody == null ? "" : htmlBody);
        if (!matcher.find()) {
            log.error("One-time code message without a code: recipient={}", to);
            throw new IllegalStateException("The one-time code message did not contain a code");
        }
        latestCodes.put(to, new InboxCode(matcher.group(1).trim(), clock.instant()));
    }

    /** Removes and returns the latest code delivered to the recipient. */
    public Optional<InboxCode> take(String recipient) {
        return Optional.ofNullable(latestCodes.remove(recipient));
    }

    /** Drops any undelivered code of a disposed principal. */
    public void discard(String recipient) {
        latestCodes.remove(recipient);
    }

    public record InboxCode(String code, Instant deliveredAt) {
    }
}
