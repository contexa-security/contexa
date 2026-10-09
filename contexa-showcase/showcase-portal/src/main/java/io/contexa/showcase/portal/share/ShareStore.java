package io.contexa.showcase.portal.share;

import io.contexa.showcase.portal.share.ExperienceResult.Score;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.security.SecureRandom;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Share cards keyed by their result values: the same result, language and address always give the same card and
 * key, and sharing it again only renews its 90 days.
 */
public class ShareStore {

    static final String KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    static final int KEY_LENGTH = 10;

    /** A stored card; {@code mine} is null when the card has Contexa's score alone. */
    public record Card(String key, String pairKey, String language, Score mine, Score contexa, String host) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final SecureRandom random = new SecureRandom();

    public ShareStore(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * The key of the card with these values: the same values keep the same key, and the image is drawn again each
     * time, so a card shared again carries the current words (H-09 #30) instead of what an earlier version drew.
     */
    public String keep(String pairKey, String language, Score mine, Score contexa, String host,
                       Supplier<byte[]> image) {
        MapSqlParameterSource values = new MapSqlParameterSource("pair", pairKey).addValue("language", language)
                .addValue("myHits", mine == null ? 0 : mine.hits()).addValue("myTotal", mine == null ? 0 : mine.total())
                .addValue("contexaHits", contexa.hits()).addValue("contexaTotal", contexa.total())
                .addValue("host", host).addValue("image", image.get());
        Optional<String> existing = jdbc.query("""
                        update share_card set last_shared_at = now(), image = :image
                         where pair_key = :pair and language = :language and my_hits = :myHits
                           and my_total = :myTotal and contexa_hits = :contexaHits
                           and contexa_total = :contexaTotal and host = :host
                        returning share_key""", values, (rs, n) -> rs.getString(1)).stream().findFirst();
        if (existing.isPresent()) {
            return existing.get();
        }
        values.addValue("key", newKey());
        return jdbc.queryForObject("""
                insert into share_card (share_key, pair_key, language, my_hits, my_total, contexa_hits,
                    contexa_total, host, image)
                values (:key, :pair, :language, :myHits, :myTotal, :contexaHits, :contexaTotal, :host, :image)
                on conflict (pair_key, language, my_hits, my_total, contexa_hits, contexa_total, host)
                do update set last_shared_at = now(), image = excluded.image
                returning share_key""", values, String.class);
    }

    public Optional<Card> find(String key) {
        return jdbc.query("""
                        select share_key, pair_key, language, my_hits, my_total, contexa_hits, contexa_total, host
                          from share_card where share_key = :key""",
                new MapSqlParameterSource("key", key),
                (rs, n) -> new Card(rs.getString(1), rs.getString(2), rs.getString(3),
                        rs.getInt(5) == 0 ? null : new Score(rs.getInt(4), rs.getInt(5)),
                        new Score(rs.getInt(6), rs.getInt(7)), rs.getString(8)))
                .stream().findFirst();
    }

    public Optional<byte[]> image(String key) {
        return jdbc.query("select image from share_card where share_key = :key",
                new MapSqlParameterSource("key", key), (rs, n) -> rs.getBytes(1)).stream().findFirst();
    }

    public static boolean validKey(String key) {
        if (key == null || key.length() != KEY_LENGTH) {
            return false;
        }
        for (int i = 0; i < key.length(); i++) {
            if (KEY_ALPHABET.indexOf(key.charAt(i)) < 0) {
                return false;
            }
        }
        return true;
    }

    private String newKey() {
        StringBuilder key = new StringBuilder(KEY_LENGTH);
        for (int i = 0; i < KEY_LENGTH; i++) {
            key.append(KEY_ALPHABET.charAt(random.nextInt(KEY_ALPHABET.length())));
        }
        return key.toString();
    }
}
