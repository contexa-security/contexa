package io.contexa.contexaiam.aiam.labs.data;

import io.contexa.contexaiam.aiam.labs.studio.domain.DataCollectionPlan;
import io.contexa.contexaiam.aiam.labs.studio.domain.IAMDataSet;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;

@Slf4j
@Service
@RequiredArgsConstructor
public class StudioQueryCollectionService {

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    /**
     * Virtual Thread 최적화된 동기 버전 (기존 인터페이스 유지)
     */
    @Transactional(readOnly = true)
    public IAMDataSet collectData(DataCollectionPlan plan) {
        Thread currentThread = Thread.currentThread();
        log.info("IAM 데이터 수집 시작 - Thread: {} (Virtual: {})",
                currentThread.getName(), currentThread.isVirtual());

        // Virtual Thread 에서 실행되도록 보장
        if (!currentThread.isVirtual()) {
            return collectDataAsync(plan).block();
        }

        // 이미 Virtual Thread 라면 직접 실행
        return executeDataCollection(plan);
    }

    /**
     * 비동기 버전 (Virtual Thread 활용)
     */
    public Mono<IAMDataSet> collectDataAsync(DataCollectionPlan plan) {
        return Mono.fromCallable(() -> executeDataCollection(plan))
                .doOnSubscribe(sub ->
                        log.info("비동기 IAM 데이터 수집 시작 - Thread: {}",
                                Thread.currentThread().getName()))
                .doOnSuccess(result ->
                        log.info("비동기 IAM 데이터 수집 완료 - Thread: {} (Virtual: {})",
                                Thread.currentThread().getName(),
                                Thread.currentThread().isVirtual()));
    }

    /**
     * 실제 데이터 수집 로직 (Virtual Thread 에서 실행)
     */
    @Transactional(readOnly = true)
    public IAMDataSet executeDataCollection(DataCollectionPlan plan) {
        IAMDataSet dataSet = new IAMDataSet();

        try {
            // 병렬로 카운트 조회 (Virtual Thread 활용)
            CompletableFuture<Integer> userCountFuture = CompletableFuture.supplyAsync(
                    () -> (int) userRepository.count(),
                    Executors.newVirtualThreadPerTaskExecutor()
            );

            CompletableFuture<Integer> groupCountFuture = CompletableFuture.supplyAsync(
                    () -> (int) groupRepository.count(),
                    Executors.newVirtualThreadPerTaskExecutor()
            );

            CompletableFuture<Integer> roleCountFuture = CompletableFuture.supplyAsync(
                    () -> (int) roleRepository.count(),
                    Executors.newVirtualThreadPerTaskExecutor()
            );

            CompletableFuture<Integer> permissionCountFuture = CompletableFuture.supplyAsync(
                    () -> (int) permissionRepository.count(),
                    Executors.newVirtualThreadPerTaskExecutor()
            );

            // 모든 카운트 조회 완료 대기
            CompletableFuture.allOf(
                    userCountFuture, groupCountFuture,
                    roleCountFuture, permissionCountFuture
            ).join();

            int totalUsers = userCountFuture.get();
            int totalGroups = groupCountFuture.get();
            int totalRoles = roleCountFuture.get();
            int totalPermissions = permissionCountFuture.get();

            log.info("DB 상태: users={}, groups={}, roles={}, permissions={} - Thread: {} (Virtual: {})",
                    totalUsers, totalGroups, totalRoles, totalPermissions,
                    Thread.currentThread().getName(), Thread.currentThread().isVirtual());

            if (totalUsers == 0 && totalGroups == 0 && totalRoles == 0 && totalPermissions == 0) {
                log.error("IAM 데이터 없음!");
                dataSet.setError("시스템에 IAM 데이터가 없습니다. 테스트 데이터를 먼저 생성해주세요.");
                return dataSet;
            }

            // 필요한 데이터를 병렬로 조회 (Virtual Thread 활용)
            CompletableFuture<Void> usersFuture = CompletableFuture.runAsync(() -> {
                if (plan.needsUsers()) {
                    Thread t = Thread.currentThread();
                    log.debug("👥 사용자 데이터 조회 시작 - Thread: {} (Virtual: {})",
                            t.getName(), t.isVirtual());
                    dataSet.setUsers(userRepository.findAllWithGroups());
                    log.info("👥 사용자 데이터 수집 완료: {}명", dataSet.getUsers().size());
                }
            }, Executors.newVirtualThreadPerTaskExecutor());

            CompletableFuture<Void> groupsFuture = CompletableFuture.runAsync(() -> {
                if (plan.needsGroups()) {
                    Thread t = Thread.currentThread();
                    log.debug("👥 그룹 데이터 조회 시작 - Thread: {} (Virtual: {})",
                            t.getName(), t.isVirtual());
                    dataSet.setGroups(groupRepository.findAllWithRelations());
                    log.info("👥 그룹 데이터 수집 완료: {}개", dataSet.getGroups().size());
                }
            }, Executors.newVirtualThreadPerTaskExecutor());

            CompletableFuture<Void> rolesFuture = CompletableFuture.runAsync(() -> {
                if (plan.needsRoles()) {
                    Thread t = Thread.currentThread();
                    log.debug("역할 데이터 조회 시작 - Thread: {} (Virtual: {})",
                            t.getName(), t.isVirtual());
                    dataSet.setRoles(roleRepository.findAllWithPermissions());
                    log.info("역할 데이터 수집 완료: {}개", dataSet.getRoles().size());
                }
            }, Executors.newVirtualThreadPerTaskExecutor());

            CompletableFuture<Void> permissionsFuture = CompletableFuture.runAsync(() -> {
                if (plan.needsPermissions() || plan.needsBusinessResources() || plan.needsBusinessActions()) {
                    Thread t = Thread.currentThread();
                    log.debug("권한 데이터 조회 시작 - Thread: {} (Virtual: {})",
                            t.getName(), t.isVirtual());
                    dataSet.setPermissions(permissionRepository.findAll());
                    log.info("권한 데이터 수집 완료: {}개", dataSet.getPermissions().size());
                }
            }, Executors.newVirtualThreadPerTaskExecutor());

            // 모든 병렬 작업 완료 대기
            CompletableFuture.allOf(usersFuture, groupsFuture, rolesFuture, permissionsFuture)
                    .join();

            // 관계 데이터 처리 (이전 데이터 의존성 때문에 순차 처리)
            if (plan.needsRelationships()) {
                handleRelationships(plan, dataSet);
            }

            log.info("IAM 데이터 수집 완료 - Thread: {} (Virtual: {})",
                    Thread.currentThread().getName(), Thread.currentThread().isVirtual());

            return dataSet;

        } catch (Exception e) {
            log.error("IAM 데이터 수집 실패", e);
            dataSet.setError("IAM 데이터 수집 중 오류 발생: " + e.getMessage());
            return dataSet;
        }
    }

    /**
     * 관계 데이터 처리 (Virtual Thread 에서 병렬 처리)
     */
    @Transactional(readOnly = true)
    public void handleRelationships(DataCollectionPlan plan, IAMDataSet dataSet) {
        CompletableFuture<Void> userRelFuture = CompletableFuture.runAsync(() -> {
            if (dataSet.getUsers() == null) {
                dataSet.setUsers(userRepository.findAllWithGroups());
            }
        }, Executors.newVirtualThreadPerTaskExecutor());

        CompletableFuture<Void> groupRelFuture = CompletableFuture.runAsync(() -> {
            if (dataSet.getGroups() == null) {
                dataSet.setGroups(groupRepository.findAllWithRelations());
            }
        }, Executors.newVirtualThreadPerTaskExecutor());

        CompletableFuture<Void> roleRelFuture = CompletableFuture.runAsync(() -> {
            if (dataSet.getRoles() == null) {
                dataSet.setRoles(roleRepository.findAllWithPermissions());
            }
        }, Executors.newVirtualThreadPerTaskExecutor());

        CompletableFuture.allOf(userRelFuture, groupRelFuture, roleRelFuture).join();
        log.info("🔗 권한 체인 관계 데이터 수집 완료");
    }
}