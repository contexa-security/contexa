package io.contexa.showcase.business;

import org.springframework.core.env.Environment;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Refuses to start a production showcase application with a default or missing secret (deck p.37, P5-SEC-02). Every
 * application checks its database password and the internal signing key here and adds its own rules; the check runs
 * only with {@code showcase.production=true}, so development stacks keep their local values. Problems name the
 * setting, never its value.
 */
public final class ProductionSafety {

    public static final String PRODUCTION = "showcase.production";
    static final int MINIMUM_PASSWORD_LENGTH = 12;
    static final int MINIMUM_KEY_BYTES = 32;
    static final int MINIMUM_DISTINCT_KEY_BYTES = 16;
    static final Set<String> WEAK_PASSWORDS = Set.of("showcase", "password", "postgres", "changeme", "secret", "admin",
            "contexa", "contexa1234!@#");

    private ProductionSafety() {
    }

    public static boolean production(Environment environment) {
        return environment.getProperty(PRODUCTION, Boolean.class, false);
    }

    /**
     * @param extra the application's own problems, already worded
     * @throws IllegalStateException listing every problem on a production application
     */
    public static void verify(Environment environment, List<String> extra) {
        if (!production(environment)) {
            return;
        }
        List<String> problems = new ArrayList<>();
        String password = environment.getProperty("spring.datasource.password");
        if (weak(password)) {
            problems.add("spring.datasource.password is missing or weak");
        }
        if (weakKey(environment.getProperty("showcase.internal.signing-key"))) {
            problems.add("showcase.internal.signing-key is missing or weak");
        }
        problems.addAll(extra);
        if (!problems.isEmpty()) {
            throw new IllegalStateException("Refusing to start in production: " + String.join("; ", problems));
        }
    }

    public static boolean weak(String password) {
        return password == null || password.isBlank() || password.length() < MINIMUM_PASSWORD_LENGTH
                || WEAK_PASSWORDS.contains(password.toLowerCase());
    }

    /** A random 32-byte key has about 30 distinct byte values; a zero-filled or repeated key has very few. */
    static boolean weakKey(String base64) {
        if (blank(base64)) {
            return true;
        }
        byte[] key;
        try {
            key = Base64.getDecoder().decode(base64.trim());
        } catch (IllegalArgumentException e) {
            return true;
        }
        if (key.length < MINIMUM_KEY_BYTES) {
            return true;
        }
        Set<Byte> distinct = new HashSet<>();
        for (byte b : key) {
            distinct.add(b);
        }
        return distinct.size() < MINIMUM_DISTINCT_KEY_BYTES;
    }

    public static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
