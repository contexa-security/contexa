package io.contexa.contexaiam.aiam.service;

import io.contexa.contexacore.domain.entity.CustomerData;
import io.contexa.contexacore.repository.CustomerDataRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * 고객 데이터 서비스
 *
 * @Protectable 어노테이션으로 보호된 메서드를 제공하여
 * 자율보안운영체제의 실제 보호 효과를 검증합니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ProtectableDataService {

    private final CustomerDataRepository customerDataRepository;

    /**
     * 보호된 고객 데이터 조회 메서드
     *
     * 이 메서드는 @Protectable 어노테이션으로 보호되어 있어
     * 정상적인 경우 CustomDynamicAuthorizationManager가 접근을 제어합니다.
     *
     * 시뮬레이션 모드:
     * - 무방비 모드: 이벤트 발행 없이 직접 호출되어 데이터 유출
     * - 방어 모드: 이벤트 발행으로 자율보안체제가 작동하여 차단
     *
     * @param customerId 고객 ID
     * @return 고객 데이터
     */
    @Transactional(readOnly = true)
    public Optional<CustomerData> getCustomerData(String customerId) {
        log.info("Attempting to access customer data for ID: {}", customerId);

        Optional<CustomerData> customerData = customerDataRepository.findById(customerId);

        if (customerData.isPresent()) {
            log.info("Customer data found for ID: {}", customerId);
            // 실제 데이터 접근이 발생했음을 기록
            logDataAccess(customerId, customerData.get());
        } else {
            log.warn("Customer data not found for ID: {}", customerId);
        }

        return customerData;
    }

    /**
     * 모든 고객 데이터 조회 (매우 위험한 작업)
     *
     * @return 모든 고객 데이터
     */
    @Transactional(readOnly = true)
    public List<CustomerData> getAllCustomerData() {
        log.warn("Attempting to access ALL customer data - CRITICAL operation");

        List<CustomerData> allData = customerDataRepository.findAll();
        log.info("Retrieved {} customer records", allData.size());

        return allData;
    }

    /**
     * 고객 데이터 수정 (쓰기 작업)
     *
     * @param customerId 고객 ID
     * @param newData 새로운 데이터
     * @return 수정된 고객 데이터
     */
    @Transactional
    public CustomerData updateCustomerData(String customerId, CustomerData newData) {
        log.warn("Attempting to UPDATE customer data for ID: {}", customerId);

        Optional<CustomerData> existing = customerDataRepository.findById(customerId);
        if (existing.isPresent()) {
            CustomerData customer = existing.get();
            customer.setName(newData.getName());
            customer.setEmail(newData.getEmail());
            customer.setPhoneNumber(newData.getPhoneNumber());
            customer.setAddress(newData.getAddress());
            customer.setCreditCardNumber(newData.getCreditCardNumber());
            customer.setSocialSecurityNumber(newData.getSocialSecurityNumber());

            CustomerData saved = customerDataRepository.save(customer);
            log.info("Customer data updated for ID: {}", customerId);
            return saved;
        } else {
            throw new RuntimeException("Customer not found: " + customerId);
        }
    }

    /**
     * 고객 데이터 삭제 (파괴적 작업)
     *
     * @param customerId 고객 ID
     */
    @Transactional
    public void deleteCustomerData(String customerId) {
        log.error("Attempting to DELETE customer data for ID: {}", customerId);

        if (customerDataRepository.existsById(customerId)) {
            customerDataRepository.deleteById(customerId);
            log.error("Customer data DELETED for ID: {}", customerId);
        } else {
            log.warn("Customer not found for deletion: {}", customerId);
        }
    }

    /**
     * 직접 데이터 접근 (보안 우회용 - 시뮬레이션 전용)
     *
     * 이 메서드는 @Protectable이 없어서 보안 체크를 우회합니다.
     * 오직 시뮬레이션 테스트에서만 사용되어야 합니다.
     *
     * @param customerId 고객 ID
     * @return 고객 데이터
     */
    public Optional<CustomerData> getCustomerDataDirect(String customerId) {
        log.error("DIRECT ACCESS to customer data (bypassing security) for ID: {}", customerId);
        return customerDataRepository.findById(customerId);
    }

    /**
     * 데이터 접근 로깅
     *
     * @param customerId 접근된 고객 ID
     * @param data 접근된 데이터
     */
    private void logDataAccess(String customerId, CustomerData data) {
        // 민감한 데이터 접근을 기록 (실제 데이터는 로그에 남기지 않음)
        log.info("Data access logged - Customer ID: {}, Data fields accessed: [name, email, phone, address, credit_card, ssn]",
                customerId);
    }
}