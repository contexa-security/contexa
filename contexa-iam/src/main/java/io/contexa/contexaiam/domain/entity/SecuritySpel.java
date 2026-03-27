package io.contexa.contexaiam.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "security_spel")
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class SecuritySpel {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 255)
    private String name;

    @Column(nullable = false, length = 2048)
    private String expression;

    @Column(length = 1024)
    private String description;

    @Column(length = 100)
    private String category;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
