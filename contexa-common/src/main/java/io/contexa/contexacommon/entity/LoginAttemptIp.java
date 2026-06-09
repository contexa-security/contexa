package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Per-IP failed login attempt counter, used for IP-dimension throttling and lockout.
 * <p>Atomic increments are performed via dedicated repository queries to avoid
 * read-modify-write race conditions under concurrent failed-login storms.</p>
 */
@Entity
@Table(name = "login_attempt_ip",
        indexes = {
                @Index(name = "idx_login_attempt_ip_address", columnList = "ip_address", unique = true),
                @Index(name = "idx_login_attempt_ip_window", columnList = "window_start_at")
        })
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginAttemptIp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", nullable = false, length = 64, unique = true)
    private String ipAddress;

    @Column(name = "failed_attempts", nullable = false)
    @Builder.Default
    private int failedAttempts = 0;

    @Column(name = "window_start_at", nullable = false)
    private LocalDateTime windowStartAt;

    @Column(name = "blocked_until")
    private LocalDateTime blockedUntil;

    @Column(name = "last_failure_at")
    private LocalDateTime lastFailureAt;

    @Column(name = "last_username", length = 255)
    private String lastUsername;
}
