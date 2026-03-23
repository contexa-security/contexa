package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "password_policy")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PasswordPolicy {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    @Builder.Default
    private int minLength = 8;

    @Column(nullable = false)
    @Builder.Default
    private int maxLength = 128;

    @Builder.Default
    private boolean requireUppercase = true;

    @Builder.Default
    private boolean requireLowercase = true;

    @Builder.Default
    private boolean requireDigit = true;

    @Builder.Default
    private boolean requireSpecialChar = false;

    @Builder.Default
    private int maxFailedAttempts = 5;

    @Builder.Default
    private int lockoutDurationMinutes = 30;

    @Builder.Default
    private int passwordExpiryDays = 90;

    @Builder.Default
    private int historyCount = 3;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
