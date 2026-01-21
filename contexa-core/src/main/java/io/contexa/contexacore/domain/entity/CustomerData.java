package io.contexa.contexacore.domain.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "customer_data")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CustomerData {

    @Id
    @Column(name = "customer_id", nullable = false, length = 50)
    private String customerId;

    @Column(name = "name", nullable = false, length = 100)
    private String name;

    @Column(name = "email", nullable = false, length = 255)
    private String email;

    @Column(name = "phone_number", length = 20)
    private String phoneNumber;

    @Column(name = "address", columnDefinition = "TEXT")
    private String address;

    @Column(name = "credit_card_number", length = 20)
    private String creditCardNumber;

    @Column(name = "social_security_number", length = 15)
    private String socialSecurityNumber;

    @Column(name = "account_balance")
    private Double accountBalance;

    @Column(name = "is_vip")
    private Boolean isVip;

    @Column(name = "sensitivity_level", length = 20)
    @Enumerated(EnumType.STRING)
    private SensitivityLevel sensitivityLevel;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "last_accessed_at")
    private LocalDateTime lastAccessedAt;

    @Column(name = "membership_tier", length = 20)
    @Enumerated(EnumType.STRING)
    private MembershipTier membershipTier;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    @Column(name = "created_date")
    private LocalDateTime createdDate;

    @Column(name = "active")
    @Builder.Default
    private Boolean active = true;

    @Column(name = "two_factor_enabled")
    @Builder.Default
    private Boolean twoFactorEnabled = false;

    @Column(name = "personal_info", columnDefinition = "TEXT")
    private String personalInfo;

    public enum SensitivityLevel {
        CRITICAL,  
        HIGH,      
        MEDIUM,    
        LOW        
    }

    public enum MembershipTier {
        PLATINUM,  
        GOLD,      
        SILVER,    
        BRONZE     
    }

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public void markAccessed() {
        lastAccessedAt = LocalDateTime.now();
    }

    public CustomerData getMaskedCopy() {
        return CustomerData.builder()
                .customerId(this.customerId)
                .name(this.name)
                .email(maskEmail(this.email))
                .phoneNumber(maskPhoneNumber(this.phoneNumber))
                .address(this.address != null ? "***MASKED***" : null)
                .creditCardNumber(maskCreditCard(this.creditCardNumber))
                .socialSecurityNumber(maskSSN(this.socialSecurityNumber))
                .accountBalance(null) 
                .isVip(this.isVip)
                .sensitivityLevel(this.sensitivityLevel)
                .createdAt(this.createdAt)
                .updatedAt(this.updatedAt)
                .lastAccessedAt(this.lastAccessedAt)
                .build();
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) return email;
        String[] parts = email.split("@");
        if (parts[0].length() > 2) {
            return parts[0].substring(0, 2) + "****@" + parts[1];
        }
        return "****@" + parts[1];
    }

    private String maskPhoneNumber(String phone) {
        if (phone == null || phone.length() < 4) return phone;
        return phone.substring(0, 3) + "****" + phone.substring(phone.length() - 4);
    }

    private String maskCreditCard(String card) {
        if (card == null || card.length() < 4) return card;
        return "**** **** **** " + card.substring(card.length() - 4);
    }

    private String maskSSN(String ssn) {
        if (ssn == null || ssn.length() < 4) return ssn;
        return "***-**-" + ssn.substring(ssn.length() - 4);
    }
}