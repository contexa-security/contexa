package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory sealed packages and inspection results for the inspection service tests. */
final class InspectionStores {

    private InspectionStores() {
    }

    static SealedEvidencePackage sealed(String packageId, Instant capturedAt) {
        return SealedEvidencePackage.builder()
                .packageId(packageId)
                .correlationId("correlation-" + packageId)
                .capturedAt(capturedAt)
                .userPromptText("=== REQUEST ===\nSubject: user-1\n")
                .rawUserPrompt("=== REQUEST ===\nSubject: user-1\n")
                .promptExecutionMetadataJson("{\"governanceDescriptor\":{\"userPromptLayoutVersion\":\""
                        + PromptInspector.V20_LAYOUT + "\"}}")
                .build();
    }

    /** The sealed packages, read as the JDBC repository reads them (period ends included, latest first). */
    static final class Packages implements SealedEvidencePackageRepository {

        private final Map<String, SealedEvidencePackage> packages = new ConcurrentHashMap<>();

        Packages add(SealedEvidencePackage evidencePackage) {
            packages.put(evidencePackage.getPackageId(), evidencePackage);
            return this;
        }

        void remove(String packageId) {
            packages.remove(packageId);
        }

        List<SealedEvidencePackage> oldestFirst() {
            return packages.values().stream().sorted(Comparator.comparing(SealedEvidencePackage::getCapturedAt)).toList();
        }

        @Override
        public SealedEvidencePackage save(SealedEvidencePackage evidencePackage) {
            add(evidencePackage);
            return evidencePackage;
        }

        @Override
        public Optional<SealedEvidencePackage> findByPackageId(String packageId) {
            return Optional.ofNullable(packages.get(packageId));
        }

        @Override
        public Optional<SealedEvidencePackage> findByCorrelationId(String correlationId) {
            return packages.values().stream().filter(item -> correlationId.equals(item.getCorrelationId())).findFirst();
        }

        @Override
        public Optional<SealedEvidencePackage> findByIdempotencyKey(String idempotencyKey) {
            return Optional.empty();
        }

        @Override
        public Page<SealedEvidencePackage> findByUserIdAndCapturedAtBetweenOrderByCapturedAtDesc(
                String userId, Instant from, Instant to, Pageable pageable) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Page<SealedEvidencePackage> findByTenantIdAndCapturedAtBetweenOrderByCapturedAtDesc(
                String tenantId, Instant from, Instant to, Pageable pageable) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Page<SealedEvidencePackage> findByCapturedAtBetweenOrderByCapturedAtDesc(
                Instant from, Instant to, Pageable pageable) {
            List<SealedEvidencePackage> within = packages.values().stream()
                    .filter(item -> !item.getCapturedAt().isBefore(from) && !item.getCapturedAt().isAfter(to))
                    .sorted(Comparator.comparing(SealedEvidencePackage::getCapturedAt).reversed())
                    .toList();
            int start = (int) Math.min(pageable.getOffset(), within.size());
            int end = Math.min(start + pageable.getPageSize(), within.size());
            return new PageImpl<>(within.subList(start, end), pageable, within.size());
        }

        @Override
        public long countByTenantIdAndCapturedAtAfter(String tenantId, Instant after) {
            return 0;
        }

        @Override
        public long deleteByExpiresAtBefore(Instant now) {
            return 0;
        }
    }

    /** The stored results by package and inspector version, with every save in order. */
    static final class Results implements PromptInspectionResultStore {

        private final Packages packages;
        private final Map<String, PromptInspectionRecord> stored = new LinkedHashMap<>();
        final List<PromptInspectionRecord> saves = new ArrayList<>();
        final Set<String> failing = ConcurrentHashMap.newKeySet();
        /** The sample share the last period removal was asked for. */
        int removedWithSample;

        Results(Packages packages) {
            this.packages = packages;
        }

        @Override
        public synchronized List<String> findUninspectedPackageIds(String inspectorVersion, int limit,
                                                                   int samplePercent) {
            return packages.oldestFirst().stream()
                    .map(SealedEvidencePackage::getPackageId)
                    .filter(id -> !stored.containsKey(id + "|" + inspectorVersion))
                    .limit(limit)
                    .toList();
        }

        @Override
        public synchronized void save(PromptInspectionResult result, PromptInspectionTrigger trigger,
                                      Instant inspectedAt) {
            if (failing.contains(result.packageId())) {
                throw new IllegalStateException("store failed for " + result.packageId());
            }
            PromptInspectionRecord record = new PromptInspectionRecord(saves.size() + 1L, result, trigger, inspectedAt);
            stored.put(result.packageId() + "|" + result.inspectorVersion(), record);
            saves.add(record);
        }

        /** The newest stored result of a package, for the tests to read. */
        public synchronized Optional<PromptInspectionRecord> findLatest(String packageId) {
            return stored.values().stream().filter(record -> packageId.equals(record.result().packageId()))
                    .max(Comparator.comparing(PromptInspectionRecord::inspectedAt));
        }

        @Override
        public synchronized List<PromptInspectionRecord> findAll(String packageId) {
            return stored.values().stream().filter(record -> packageId.equals(record.result().packageId()))
                    .sorted(Comparator.comparing(PromptInspectionRecord::inspectedAt).reversed())
                    .toList();
        }

        @Override
        public synchronized int removeResults(String inspectorVersion, Instant from, Instant to, int samplePercent) {
            removedWithSample = samplePercent;
            int removed = 0;
            for (String packageId : capturedIn(from, to)) {
                if (stored.remove(packageId + "|" + inspectorVersion) != null) {
                    removed++;
                }
            }
            return removed;
        }

        @Override
        public synchronized int removeCleanPackagesCapturedBefore(Instant before, int limit) {
            Set<PromptInspectionVerdict> clean = Set.of(PromptInspectionVerdict.PASS,
                    PromptInspectionVerdict.NOT_APPLICABLE);
            List<String> removed = packages.oldestFirst().stream()
                    .filter(evidencePackage -> evidencePackage.getCapturedAt().isBefore(before))
                    .map(SealedEvidencePackage::getPackageId)
                    .filter(id -> findLatest(id).map(record -> clean.contains(record.result().verdict()))
                            .orElse(false))
                    .limit(limit)
                    .toList();
            for (String packageId : removed) {
                stored.values().removeIf(record -> packageId.equals(record.result().packageId()));
                packages.remove(packageId);
            }
            return removed.size();
        }

        @Override
        public synchronized PeriodCount countPeriod(String inspectorVersion, Instant from, Instant to,
                                                    int samplePercent) {
            List<String> period = capturedIn(from, to);
            return new PeriodCount(period.size(),
                    period.stream().filter(id -> !stored.containsKey(id + "|" + inspectorVersion)).count());
        }

        private List<String> capturedIn(Instant from, Instant to) {
            return packages.oldestFirst().stream()
                    .filter(evidencePackage -> !evidencePackage.getCapturedAt().isBefore(from)
                            && !evidencePackage.getCapturedAt().isAfter(to))
                    .map(SealedEvidencePackage::getPackageId)
                    .toList();
        }
    }
}
