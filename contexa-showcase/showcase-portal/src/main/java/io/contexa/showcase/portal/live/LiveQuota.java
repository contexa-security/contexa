package io.contexa.showcase.portal.live;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.sql.Date;
import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;

/**
 * The daily live-run limits (deck p.28): per visitor cookie and per address, counted only for new combinations that
 * really run. The address is stored as a keyed hash that changes every day (UTC), so neither the address nor a
 * long-lived identifier is kept.
 */
public class LiveQuota {

    public enum Refusal { VISITOR_LIMIT, ADDRESS_LIMIT, AGENT_LIMIT }

    /** What a run is, for its cost in points (docs/agent Agent중심-화면 AC-2). */
    public enum Kind { PERSON, AGENT, BURST }

    /** The points of a run by its kind; a person's run is one point, so the daily limits read as runs for a person. */
    public record Weights(int person, int agent, int burst) {

        public static Weights defaults() {
            return new Weights(1, 3, 5);
        }

        public int of(Kind kind) {
            return switch (kind) {
                case PERSON -> person;
                case AGENT -> agent;
                case BURST -> burst;
            };
        }
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final byte[] addressKey;
    private final int visitorDaily;
    private final int addressDaily;
    private final Weights weights;
    private final int agentDaily;
    private final Clock clock;

    /** The limits in points, an agent run worth three, and two agent runs a visitor per day. */
    public LiveQuota(NamedParameterJdbcTemplate jdbc, String signingKeyBase64, int visitorDaily, int addressDaily,
                     Clock clock) {
        this(jdbc, signingKeyBase64, visitorDaily, addressDaily, Weights.defaults(), 2, clock);
    }

    /**
     * @param visitorDaily the points a visitor may use in a day
     * @param addressDaily the points an address may use in a day
     * @param agentDaily   the agent runs a visitor may start in a day, whatever points are left
     */
    public LiveQuota(NamedParameterJdbcTemplate jdbc, String signingKeyBase64, int visitorDaily, int addressDaily,
                     Weights weights, int agentDaily, Clock clock) {
        this.jdbc = jdbc;
        this.addressKey = hmac(Base64.getDecoder().decode(signingKeyBase64), "showcase-live-address-v1");
        this.visitorDaily = visitorDaily;
        this.addressDaily = addressDaily;
        this.weights = weights;
        this.agentDaily = agentDaily;
        this.clock = clock;
    }

    public int visitorDaily() {
        return visitorDaily;
    }

    public int agentDaily() {
        return agentDaily;
    }

    public Weights weights() {
        return weights;
    }

    /** The points the visitor has left today. */
    public int remaining(String visitorHash) {
        return Math.max(0, visitorDaily - used("VISITOR", visitorHash));
    }

    /** The agent runs the visitor may still start today: by the daily agent limit and by the points left. */
    public int remainingAgentRuns(String visitorHash) {
        int byLimit = Math.max(0, agentDaily - used("AGENT", visitorHash));
        int byPoints = weights.agent() <= 0 ? byLimit : remaining(visitorHash) / weights.agent();
        return Math.min(byLimit, byPoints);
    }

    /** Takes one person's run from both limits, or none when either is used up. */
    public synchronized Refusal take(String visitorHash, String address) {
        return take(visitorHash, address, Kind.PERSON);
    }

    /** Takes a run of the kind, in its points, from the limits, or none when one of them cannot hold it. */
    public synchronized Refusal take(String visitorHash, String address, Kind kind) {
        String addressHash = addressHash(address);
        int points = weights.of(kind);
        if (countsAsAgentRun(kind) && used("AGENT", visitorHash) >= agentDaily) {
            return Refusal.AGENT_LIMIT;
        }
        if (used("VISITOR", visitorHash) + points > visitorDaily) {
            return Refusal.VISITOR_LIMIT;
        }
        if (addressHash != null && used("ADDRESS", addressHash) + points > addressDaily) {
            return Refusal.ADDRESS_LIMIT;
        }
        add("VISITOR", visitorHash, points);
        if (addressHash != null) {
            add("ADDRESS", addressHash, points);
        }
        if (countsAsAgentRun(kind)) {
            add("AGENT", visitorHash, 1);
        }
        return null;
    }

    /** Gives a person's run back when it could not start or failed for a technical reason. */
    public synchronized void giveBack(String visitorHash, String address) {
        giveBack(visitorHash, address, Kind.PERSON);
    }

    /** Gives a run of the kind back: its points and, for an agent run, its place in the daily agent count. */
    public synchronized void giveBack(String visitorHash, String address, Kind kind) {
        int points = weights.of(kind);
        add("VISITOR", visitorHash, -points);
        String addressHash = addressHash(address);
        if (addressHash != null) {
            add("ADDRESS", addressHash, -points);
        }
        if (countsAsAgentRun(kind)) {
            add("AGENT", visitorHash, -1);
        }
    }

    /** A burst is an agent's run too (docs/agent Agent중심-화면 AS-13): it counts in the visitor's daily agent runs. */
    private static boolean countsAsAgentRun(Kind kind) {
        return kind == Kind.AGENT || kind == Kind.BURST;
    }

    String addressHash(String address) {
        if (address == null || address.isBlank()) {
            return null;
        }
        return HexFormat.of().formatHex(hmac(addressKey, today() + "|" + address));
    }

    private int used(String kind, String subject) {
        Integer used = jdbc.query("""
                        select used from live_quota where day = :day and subject_kind = :kind and subject_hash = :subject""",
                params(kind, subject), (rs, n) -> rs.getInt(1)).stream().findFirst().orElse(0);
        return used;
    }

    private void add(String kind, String subject, int delta) {
        jdbc.update("""
                        insert into live_quota (day, subject_kind, subject_hash, used)
                        values (:day, :kind, :subject, greatest(:delta, 0))
                        on conflict (day, subject_kind, subject_hash)
                        do update set used = greatest(live_quota.used + :delta, 0)""",
                params(kind, subject).addValue("delta", delta));
    }

    private MapSqlParameterSource params(String kind, String subject) {
        return new MapSqlParameterSource("day", Date.valueOf(today())).addValue("kind", kind)
                .addValue("subject", subject);
    }

    private LocalDate today() {
        return LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
    }

    private static byte[] hmac(byte[] key, String text) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(text.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is not available", e);
        }
    }
}
