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

    public enum Refusal { VISITOR_LIMIT, ADDRESS_LIMIT }

    private final NamedParameterJdbcTemplate jdbc;
    private final byte[] addressKey;
    private final int visitorDaily;
    private final int addressDaily;
    private final Clock clock;

    public LiveQuota(NamedParameterJdbcTemplate jdbc, String signingKeyBase64, int visitorDaily, int addressDaily,
                     Clock clock) {
        this.jdbc = jdbc;
        this.addressKey = hmac(Base64.getDecoder().decode(signingKeyBase64), "showcase-live-address-v1");
        this.visitorDaily = visitorDaily;
        this.addressDaily = addressDaily;
        this.clock = clock;
    }

    public int visitorDaily() {
        return visitorDaily;
    }

    public int remaining(String visitorHash) {
        return Math.max(0, visitorDaily - used("VISITOR", visitorHash));
    }

    /** Takes one run from both limits, or none when either is used up. */
    public synchronized Refusal take(String visitorHash, String address) {
        String addressHash = addressHash(address);
        if (used("VISITOR", visitorHash) >= visitorDaily) {
            return Refusal.VISITOR_LIMIT;
        }
        if (addressHash != null && used("ADDRESS", addressHash) >= addressDaily) {
            return Refusal.ADDRESS_LIMIT;
        }
        add("VISITOR", visitorHash, 1);
        if (addressHash != null) {
            add("ADDRESS", addressHash, 1);
        }
        return null;
    }

    /** Gives a run back when it could not start or failed for a technical reason. */
    public synchronized void giveBack(String visitorHash, String address) {
        add("VISITOR", visitorHash, -1);
        String addressHash = addressHash(address);
        if (addressHash != null) {
            add("ADDRESS", addressHash, -1);
        }
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
