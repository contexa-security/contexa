package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.CustomerData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * 고객 데이터 레포지토리
 *
 * 실제 데이터베이스와 연동하여 고객 데이터를 관리합니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
@Repository
public interface CustomerDataRepository extends JpaRepository<CustomerData, String> {

    /**
     * 이메일로 고객 조회
     *
     * @param email 이메일 주소
     * @return 고객 데이터
     */
    Optional<CustomerData> findByEmail(String email);

    /**
     * VIP 고객 목록 조회
     *
     * @param isVip VIP 여부
     * @return VIP 고객 목록
     */
    List<CustomerData> findByIsVip(Boolean isVip);

    /**
     * 민감도 레벨별 고객 데이터 조회
     *
     * @param sensitivityLevel 민감도 레벨
     * @return 해당 레벨의 고객 데이터 목록
     */
    List<CustomerData> findBySensitivityLevel(CustomerData.SensitivityLevel sensitivityLevel);

    /**
     * 계좌 잔액이 특정 금액 이상인 고객 조회
     *
     * @param minBalance 최소 잔액
     * @return 고객 목록
     */
    @Query("SELECT c FROM CustomerData c WHERE c.accountBalance >= :minBalance")
    List<CustomerData> findCustomersWithMinimumBalance(@Param("minBalance") Double minBalance);

    /**
     * 최근 접근된 고객 데이터 조회
     *
     * @return 최근 접근된 상위 10개 고객 데이터
     */
    @Query("SELECT c FROM CustomerData c WHERE c.lastAccessedAt IS NOT NULL ORDER BY c.lastAccessedAt DESC")
    List<CustomerData> findRecentlyAccessedCustomers();

    /**
     * 민감한 데이터를 가진 고객 수 조회
     *
     * @return CRITICAL 또는 HIGH 레벨 고객 수
     */
    @Query("SELECT COUNT(c) FROM CustomerData c WHERE c.sensitivityLevel IN ('CRITICAL', 'HIGH')")
    Long countSensitiveCustomers();
}