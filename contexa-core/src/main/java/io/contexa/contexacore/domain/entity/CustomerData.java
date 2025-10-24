package io.contexa.contexacore.domain.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 고객 데이터 엔티티
 *
 * 실제 고객 개인정보를 담고 있는 엔티티로,
 * 시뮬레이션을 통해 데이터 유출 시나리오를 검증합니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
@Entity
@Table(name = "customer_data")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CustomerData {

    /**
     * 고객 ID (Primary Key)
     */
    @Id
    @Column(name = "customer_id", nullable = false, length = 50)
    private String customerId;

    /**
     * 고객 이름
     */
    @Column(name = "name", nullable = false, length = 100)
    private String name;

    /**
     * 이메일 주소
     */
    @Column(name = "email", nullable = false, length = 255)
    private String email;

    /**
     * 전화번호
     */
    @Column(name = "phone_number", length = 20)
    private String phoneNumber;

    /**
     * 주소
     */
    @Column(name = "address", columnDefinition = "TEXT")
    private String address;

    /**
     * 신용카드 번호 (마스킹된 형태로 저장)
     */
    @Column(name = "credit_card_number", length = 20)
    private String creditCardNumber;

    /**
     * 주민등록번호 (마스킹된 형태로 저장)
     */
    @Column(name = "social_security_number", length = 15)
    private String socialSecurityNumber;

    /**
     * 계좌 잔액
     */
    @Column(name = "account_balance")
    private Double accountBalance;

    /**
     * VIP 여부
     */
    @Column(name = "is_vip")
    private Boolean isVip;

    /**
     * 데이터 민감도 레벨
     * CRITICAL: 매우 민감 (SSN, 신용카드)
     * HIGH: 높음 (계좌 정보)
     * MEDIUM: 중간 (주소, 전화번호)
     * LOW: 낮음 (이름, 이메일)
     */
    @Column(name = "sensitivity_level", length = 20)
    @Enumerated(EnumType.STRING)
    private SensitivityLevel sensitivityLevel;

    /**
     * 생성 일시
     */
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    /**
     * 수정 일시
     */
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    /**
     * 마지막 접근 일시
     */
    @Column(name = "last_accessed_at")
    private LocalDateTime lastAccessedAt;

    /**
     * 회원 등급
     */
    @Column(name = "membership_tier", length = 20)
    @Enumerated(EnumType.STRING)
    private MembershipTier membershipTier;

    /**
     * 마지막 로그인
     */
    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    /**
     * 가입일
     */
    @Column(name = "created_date")
    private LocalDateTime createdDate;

    /**
     * 활성 상태
     */
    @Column(name = "active")
    private Boolean active = true;

    /**
     * 2FA 활성화 여부
     */
    @Column(name = "two_factor_enabled")
    private Boolean twoFactorEnabled = false;

    /**
     * 추가 개인정보 (JSON)
     */
    @Column(name = "personal_info", columnDefinition = "TEXT")
    private String personalInfo;

    /**
     * 데이터 민감도 레벨
     */
    public enum SensitivityLevel {
        CRITICAL,  // 매우 민감한 데이터
        HIGH,      // 높은 민감도
        MEDIUM,    // 중간 민감도
        LOW        // 낮은 민감도
    }

    /**
     * 회원 등급
     */
    public enum MembershipTier {
        PLATINUM,  // 플래티넘
        GOLD,      // 골드
        SILVER,    // 실버
        BRONZE     // 브론즈
    }

    /**
     * 생성 시 자동 타임스탬프 설정
     */
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    /**
     * 수정 시 자동 타임스탬프 갱신
     */
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    /**
     * 데이터 접근 시 타임스탬프 갱신
     */
    public void markAccessed() {
        lastAccessedAt = LocalDateTime.now();
    }

    /**
     * 민감한 데이터 마스킹
     *
     * @return 마스킹된 데이터를 가진 CustomerData 복사본
     */
    public CustomerData getMaskedCopy() {
        return CustomerData.builder()
                .customerId(this.customerId)
                .name(this.name)
                .email(maskEmail(this.email))
                .phoneNumber(maskPhoneNumber(this.phoneNumber))
                .address(this.address != null ? "***MASKED***" : null)
                .creditCardNumber(maskCreditCard(this.creditCardNumber))
                .socialSecurityNumber(maskSSN(this.socialSecurityNumber))
                .accountBalance(null) // 잔액 정보는 숨김
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