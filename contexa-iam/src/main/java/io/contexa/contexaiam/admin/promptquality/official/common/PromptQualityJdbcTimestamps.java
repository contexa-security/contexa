package io.contexa.contexaiam.admin.promptquality.official.common;

import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public final class PromptQualityJdbcTimestamps {

    private static final ZoneId KOREA_ZONE = ZoneId.of("Asia/Seoul");
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private PromptQualityJdbcTimestamps() {
    }

    public static String nowText() {
        return LocalDateTime.now(KOREA_ZONE).format(FORMATTER);
    }

    public static Timestamp toTimestamp(String value) {
        String normalized = StringUtils.hasText(value) ? value.trim().replace('T', ' ') : null;
        if (!StringUtils.hasText(normalized)) {
            normalized = nowText();
        }
        if (normalized.length() > 19) {
            normalized = normalized.substring(0, 19);
        }
        return Timestamp.valueOf(LocalDateTime.parse(normalized, FORMATTER));
    }

    public static String toText(Timestamp value) {
        return value == null ? null : value.toLocalDateTime().format(FORMATTER);
    }

    public static String toText(LocalDateTime value) {
        return value == null ? null : value.format(FORMATTER);
    }
}
