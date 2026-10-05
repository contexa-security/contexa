package io.contexa.showcase.workload.contexa.observation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Isolation evidence from a prompt (plan section 7, T5 to T7): the run principals the prompt mentions, and a hash of
 * the prompt with everything that legitimately differs between two runs replaced by placeholders (the run prefix of
 * principal names, run organization and tenant, UUIDs, HTTP session IDs, timestamps, the wall-clock minute of the
 * sign-in record, the host part of addresses). Two runs of the same request must give the same normalised hash; a
 * run's prompt must mention no principal but its own.
 * <p>
 * The engine writes the MFA completion into the session timeline with the server clock, while request events carry
 * the observed company time (identity AbstractMfaAuthenticationSuccessHandler), so that minute is a wall-clock time
 * of the run, not of the scenario.
 */
public final class PromptFingerprint {

    static final Pattern PRINCIPAL = Pattern.compile("v[0-9a-f]{12}(-[a-z]{2,3}-[a-z0-9]{1,3})");
    /** The run prefix is replaced; the employee key stays, since another employee is another context. */
    private static final List<Normalisation> NORMALISATIONS = List.of(
            new Normalisation(PRINCIPAL, "<RUN>$1"),
            new Normalisation(Pattern.compile("(org|tenant)-(tpl-)?[0-9a-f]{12}"), "<$1>"),
            new Normalisation(Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
                    "<UUID>"),
            new Normalisation(Pattern.compile("\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}(:\\d{2}(\\.\\d+)?)?(Z|[+-]\\d{2}:?\\d{2})?"),
                    "<TIME>"),
            new Normalisation(Pattern.compile("\\b[0-9A-F]{32}\\b"), "<SESSION>"),
            new Normalisation(Pattern.compile("\\b\\d{2}:\\d{2}( \\| MFA_COMPLETED)"), "<CLOCK>$1"),
            new Normalisation(Pattern.compile("\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\.\\d{1,3}\\b"), "$1.x"),
            new Normalisation(Pattern.compile("\\b\\d{13}\\b"), "<EPOCH_MS>"));

    private record Normalisation(Pattern pattern, String replacement) {
    }

    public record Fingerprint(String normalisedSha256, Set<String> principals, int length) {
    }

    private PromptFingerprint() {
    }

    public static Fingerprint of(String prompt) {
        Set<String> principals = new TreeSet<>();
        Matcher matcher = PRINCIPAL.matcher(prompt);
        while (matcher.find()) {
            principals.add(matcher.group());
        }
        return new Fingerprint(sha256(normalise(prompt)), principals, prompt.length());
    }

    public static String normalise(String prompt) {
        String text = prompt;
        for (Normalisation normalisation : NORMALISATIONS) {
            text = normalisation.pattern().matcher(text).replaceAll(normalisation.replacement());
        }
        return text;
    }

    private static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
