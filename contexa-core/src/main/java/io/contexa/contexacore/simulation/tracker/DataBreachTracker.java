package io.contexa.contexacore.simulation.tracker;

import io.contexa.contexacore.domain.entity.CustomerData;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 데이터 유출 추적기
 *
 * 시뮬레이션 중 실제로 유출된 데이터를 추적하고 기록합니다.
 * 각 공격 시도별로 접근/유출된 데이터를 상세히 추적합니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Component
public class DataBreachTracker {

    /**
     * 캠페인별 유출 기록
     */
    private final Map<String, CampaignBreachRecord> campaignRecords = new ConcurrentHashMap<>();

    /**
     * 공격별 유출 기록
     */
    private final Map<String, AttackBreachRecord> attackRecords = new ConcurrentHashMap<>();

    /**
     * 데이터 유출 기록
     *
     * @param campaignId 캠페인 ID
     * @param attackId 공격 ID
     * @param attackType 공격 유형
     * @param data 유출된 데이터
     * @param simulationMode 시뮬레이션 모드
     */
    public void recordDataBreach(String campaignId, String attackId, String attackType,
                                 CustomerData data, String simulationMode) {
        if (data == null) {
            return;
        }

        LocalDateTime breachTime = LocalDateTime.now();

        // 캠페인 레벨 기록
        CampaignBreachRecord campaignRecord = campaignRecords.computeIfAbsent(
            campaignId, k -> new CampaignBreachRecord(campaignId)
        );
        campaignRecord.addBreach(data, attackType, simulationMode);

        // 공격 레벨 기록
        AttackBreachRecord attackRecord = attackRecords.computeIfAbsent(
            attackId, k -> new AttackBreachRecord(attackId, attackType)
        );
        attackRecord.addBreachedData(data, breachTime);

        // 로그 기록 (실제 데이터는 기록하지 않음, ID만 기록)
        log.warn("DATA BREACH RECORDED - Campaign: {}, Attack: {} ({}), Mode: {}, Customer: {}, Sensitivity: {}",
                campaignId, attackId, attackType, simulationMode,
                data.getCustomerId(), data.getSensitivityLevel());
    }

    /**
     * 데이터 접근 시도 기록 (유출 실패 포함)
     *
     * @param campaignId 캠페인 ID
     * @param attackId 공격 ID
     * @param attackType 공격 유형
     * @param customerId 접근 시도한 고객 ID
     * @param success 성공 여부
     * @param simulationMode 시뮬레이션 모드
     */
    public void recordAccessAttempt(String campaignId, String attackId, String attackType,
                                   String customerId, boolean success, String simulationMode) {
        CampaignBreachRecord campaignRecord = campaignRecords.computeIfAbsent(
            campaignId, k -> new CampaignBreachRecord(campaignId)
        );
        campaignRecord.recordAttempt(success);

        AttackBreachRecord attackRecord = attackRecords.computeIfAbsent(
            attackId, k -> new AttackBreachRecord(attackId, attackType)
        );
        attackRecord.recordAttempt(success);

        log.info("Access attempt - Campaign: {}, Attack: {} ({}), Customer: {}, Success: {}, Mode: {}",
                campaignId, attackId, attackType, customerId, success, simulationMode);
    }

    /**
     * 간단한 유출 기록 메서드
     *
     * @param campaignId 캠페인 ID
     * @param attackId 공격 ID
     * @param breachedRecords 유출 레코드 수
     * @param mode 시뮬레이션 모드
     */
    public void recordBreach(String campaignId, String attackId, int breachedRecords, String mode) {
        CampaignBreachRecord campaignRecord = campaignRecords.computeIfAbsent(
            campaignId, k -> new CampaignBreachRecord(campaignId)
        );
        campaignRecord.addBreachCount(breachedRecords, mode);

        log.info("Breach recorded - Campaign: {}, Attack: {}, Records: {}, Mode: {}",
                campaignId, attackId, breachedRecords, mode);
    }

    /**
     * 캠페인별 유출 통계 조회
     *
     * @param campaignId 캠페인 ID
     * @return 유출 통계
     */
    public BreachStatistics getCampaignStatistics(String campaignId) {
        CampaignBreachRecord record = campaignRecords.get(campaignId);
        if (record == null) {
            return new BreachStatistics();
        }
        return record.getStatistics();
    }

    /**
     * 공격별 유출 상세 조회
     *
     * @param attackId 공격 ID
     * @return 유출 상세 정보
     */
    public AttackBreachDetail getAttackDetail(String attackId) {
        AttackBreachRecord record = attackRecords.get(attackId);
        if (record == null) {
            return null;
        }
        return record.getDetail();
    }

    /**
     * 전체 통계 초기화
     */
    public void clear() {
        campaignRecords.clear();
        attackRecords.clear();
        log.info("All breach tracking records cleared");
    }

    /**
     * 캠페인별 유출 기록
     */
    @Data
    private static class CampaignBreachRecord {
        private final String campaignId;
        private final AtomicInteger totalAttempts = new AtomicInteger(0);
        private final AtomicInteger successfulBreaches = new AtomicInteger(0);
        private final AtomicInteger blockedAttempts = new AtomicInteger(0);
        private final Map<String, AtomicInteger> breachesByType = new ConcurrentHashMap<>();
        private final Map<String, AtomicInteger> breachesByMode = new ConcurrentHashMap<>();
        private final Set<String> breachedCustomerIds = ConcurrentHashMap.newKeySet();
        private final AtomicLong totalRecordsExposed = new AtomicLong(0);
        private final Map<CustomerData.SensitivityLevel, AtomicInteger> breachesBySensitivity =
            new ConcurrentHashMap<>();

        public CampaignBreachRecord(String campaignId) {
            this.campaignId = campaignId;
        }

        public void addBreach(CustomerData data, String attackType, String mode) {
            successfulBreaches.incrementAndGet();
            breachesByType.computeIfAbsent(attackType, k -> new AtomicInteger(0)).incrementAndGet();
            breachesByMode.computeIfAbsent(mode, k -> new AtomicInteger(0)).incrementAndGet();
            breachedCustomerIds.add(data.getCustomerId());
            totalRecordsExposed.incrementAndGet();

            if (data.getSensitivityLevel() != null) {
                breachesBySensitivity.computeIfAbsent(
                    data.getSensitivityLevel(), k -> new AtomicInteger(0)
                ).incrementAndGet();
            }
        }

        public void recordAttempt(boolean success) {
            totalAttempts.incrementAndGet();
            if (!success) {
                blockedAttempts.incrementAndGet();
            }
        }

        public void addBreachCount(int count, String mode) {
            successfulBreaches.addAndGet(count);
            breachesByMode.computeIfAbsent(mode, k -> new AtomicInteger(0)).addAndGet(count);
            totalRecordsExposed.addAndGet(count);
        }

        public BreachStatistics getStatistics() {
            BreachStatistics stats = new BreachStatistics();
            stats.totalAttempts = totalAttempts.get();
            stats.successfulBreaches = successfulBreaches.get();
            stats.blockedAttempts = blockedAttempts.get();
            stats.breachRate = totalAttempts.get() > 0 ?
                (double) successfulBreaches.get() / totalAttempts.get() * 100 : 0.0;
            stats.uniqueCustomersBreached = breachedCustomerIds.size();
            stats.totalRecordsExposed = totalRecordsExposed.get();
            stats.breachesByAttackType = new HashMap<>();
            breachesByType.forEach((k, v) -> stats.breachesByAttackType.put(k, v.get()));
            stats.breachesByMode = new HashMap<>();
            breachesByMode.forEach((k, v) -> stats.breachesByMode.put(k, v.get()));
            stats.breachesBySensitivity = new HashMap<>();
            breachesBySensitivity.forEach((k, v) -> stats.breachesBySensitivity.put(k.name(), v.get()));
            return stats;
        }
    }

    /**
     * 공격별 유출 기록
     */
    @Data
    private static class AttackBreachRecord {
        private final String attackId;
        private final String attackType;
        private final List<BreachedDataEntry> breachedData = new ArrayList<>();
        private final AtomicInteger attempts = new AtomicInteger(0);
        private final AtomicInteger successes = new AtomicInteger(0);
        private LocalDateTime firstBreachTime;
        private LocalDateTime lastBreachTime;

        public AttackBreachRecord(String attackId, String attackType) {
            this.attackId = attackId;
            this.attackType = attackType;
        }

        public synchronized void addBreachedData(CustomerData data, LocalDateTime time) {
            breachedData.add(new BreachedDataEntry(
                data.getCustomerId(),
                data.getSensitivityLevel(),
                time
            ));
            successes.incrementAndGet();

            if (firstBreachTime == null) {
                firstBreachTime = time;
            }
            lastBreachTime = time;
        }

        public void recordAttempt(boolean success) {
            attempts.incrementAndGet();
            if (success) {
                successes.incrementAndGet();
            }
        }

        public AttackBreachDetail getDetail() {
            AttackBreachDetail detail = new AttackBreachDetail();
            detail.attackId = attackId;
            detail.attackType = attackType;
            detail.totalAttempts = attempts.get();
            detail.successfulBreaches = successes.get();
            detail.breachRate = attempts.get() > 0 ?
                (double) successes.get() / attempts.get() * 100 : 0.0;
            detail.breachedCustomerIds = breachedData.stream()
                .map(e -> e.customerId)
                .toList();
            detail.firstBreachTime = firstBreachTime;
            detail.lastBreachTime = lastBreachTime;
            return detail;
        }
    }

    /**
     * 캠페인의 모드별 유출 수 조회
     */
    public Map<String, Integer> getBreachCountByMode(String campaignId) {
        Map<String, Integer> result = new HashMap<>();

        CampaignBreachRecord campaign = campaignRecords.get(campaignId);
        if (campaign == null) {
            return result;
        }

        // breachesByMode 맵에서 직접 가져오기
        campaign.breachesByMode.forEach((mode, count) -> {
            result.put(mode, count.get());
        });

        // 기본값 설정
        if (!result.containsKey("UNPROTECTED")) {
            result.put("UNPROTECTED", 0);
        }
        if (!result.containsKey("PROTECTED")) {
            result.put("PROTECTED", 0);
        }

        return result;
    }

    /**
     * 캠페인의 민감도별 유출 수 조회
     */
    public Map<String, Integer> getBreachCountBySensitivity(String campaignId) {
        Map<String, Integer> result = new HashMap<>();

        CampaignBreachRecord campaign = campaignRecords.get(campaignId);
        if (campaign == null) {
            return result;
        }

        // breachesBySensitivity 맵에서 직접 가져오기
        campaign.breachesBySensitivity.forEach((sensitivity, count) -> {
            result.put(sensitivity.name(), count.get());
        });

        return result;
    }

    /**
     * 유출된 데이터 항목
     */
    @Data
    private static class BreachedDataEntry {
        private final String customerId;
        private final CustomerData.SensitivityLevel sensitivityLevel;
        private final LocalDateTime breachTime;

        public BreachedDataEntry(String customerId, CustomerData.SensitivityLevel sensitivityLevel,
                                LocalDateTime breachTime) {
            this.customerId = customerId;
            this.sensitivityLevel = sensitivityLevel;
            this.breachTime = breachTime;
        }
    }

    /**
     * 유출 통계
     */
    @Data
    public static class BreachStatistics {
        private int totalAttempts;
        private int successfulBreaches;
        private int blockedAttempts;
        private double breachRate;
        private int uniqueCustomersBreached;
        private long totalRecordsExposed;
        private Map<String, Integer> breachesByAttackType;
        private Map<String, Integer> breachesByMode;
        private Map<String, Integer> breachesBySensitivity;
    }

    /**
     * 공격별 유출 상세
     */
    @Data
    public static class AttackBreachDetail {
        private String attackId;
        private String attackType;
        private int totalAttempts;
        private int successfulBreaches;
        private double breachRate;
        private List<String> breachedCustomerIds;
        private LocalDateTime firstBreachTime;
        private LocalDateTime lastBreachTime;
    }
}