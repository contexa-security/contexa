package io.contexa.contexaiam.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "WIZARD_SESSION")
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class WizardSession {

    @Id
    @Column(name = "session_id", length = 36)
    private String id;

    @Lob
    @Column(name = "context_data", nullable = false, columnDefinition = "TEXT")
    private String contextData;

    @Column(nullable = false)
    private String ownerUserId;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    public static WizardSession create(String id, String contextData, String ownerUserId, int expirationMinutes) {
        WizardSession session = new WizardSession();
        session.setId(id);
        session.setContextData(contextData);
        session.setOwnerUserId(ownerUserId);
        session.setCreatedAt(LocalDateTime.now());
        session.setExpiresAt(LocalDateTime.now().plusMinutes(expirationMinutes));
        return session;
    }
}