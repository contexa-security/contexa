package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.CustomerData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CustomerDataRepository extends JpaRepository<CustomerData, String> {

    Optional<CustomerData> findByEmail(String email);

    List<CustomerData> findByIsVip(Boolean isVip);

    List<CustomerData> findBySensitivityLevel(CustomerData.SensitivityLevel sensitivityLevel);

    @Query("SELECT c FROM CustomerData c WHERE c.accountBalance >= :minBalance")
    List<CustomerData> findCustomersWithMinimumBalance(@Param("minBalance") Double minBalance);

    @Query("SELECT c FROM CustomerData c WHERE c.lastAccessedAt IS NOT NULL ORDER BY c.lastAccessedAt DESC")
    List<CustomerData> findRecentlyAccessedCustomers();

    @Query("SELECT COUNT(c) FROM CustomerData c WHERE c.sensitivityLevel IN ('CRITICAL', 'HIGH')")
    Long countSensitiveCustomers();
}