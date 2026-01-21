package io.contexa.contexaiam.aiam.labs.data;

import io.contexa.contexaiam.aiam.labs.studio.domain.DataCollectionPlan;
import io.contexa.contexaiam.aiam.labs.studio.domain.IAMDataSet;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;

@Slf4j
@RequiredArgsConstructor
public class StudioQueryCollectionService {

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    @Transactional(readOnly = true)
    public IAMDataSet collectData(DataCollectionPlan plan) {
        Thread currentThread = Thread.currentThread();

        if (!currentThread.isVirtual()) {
            return collectDataAsync(plan).block();
        }

        return executeDataCollection(plan);
    }

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

    @Transactional(readOnly = true)
    public IAMDataSet executeDataCollection(DataCollectionPlan plan) {
        IAMDataSet dataSet = new IAMDataSet();

        try {
            
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

            CompletableFuture.allOf(
                    userCountFuture, groupCountFuture,
                    roleCountFuture, permissionCountFuture
            ).join();

            int totalUsers = userCountFuture.get();
            int totalGroups = groupCountFuture.get();
            int totalRoles = roleCountFuture.get();
            int totalPermissions = permissionCountFuture.get();

            if (totalUsers == 0 && totalGroups == 0 && totalRoles == 0 && totalPermissions == 0) {
                log.error("IAM 데이터 없음!");
                dataSet.setError("시스템에 IAM 데이터가 없습니다. 테스트 데이터를 먼저 생성해주세요.");
                return dataSet;
            }

            CompletableFuture<Void> usersFuture = CompletableFuture.runAsync(() -> {
                if (plan.needsUsers()) {
                    Thread t = Thread.currentThread();
                                        dataSet.setUsers(userRepository.findAllWithGroups());
                                    }
            }, Executors.newVirtualThreadPerTaskExecutor());

            CompletableFuture<Void> groupsFuture = CompletableFuture.runAsync(() -> {
                if (plan.needsGroups()) {
                    Thread t = Thread.currentThread();
                                        dataSet.setGroups(groupRepository.findAllWithRelations());
                                    }
            }, Executors.newVirtualThreadPerTaskExecutor());

            CompletableFuture<Void> rolesFuture = CompletableFuture.runAsync(() -> {
                if (plan.needsRoles()) {
                    Thread t = Thread.currentThread();
                                        dataSet.setRoles(roleRepository.findAllWithPermissions());
                                    }
            }, Executors.newVirtualThreadPerTaskExecutor());

            CompletableFuture<Void> permissionsFuture = CompletableFuture.runAsync(() -> {
                if (plan.needsPermissions() || plan.needsBusinessResources() || plan.needsBusinessActions()) {
                    Thread t = Thread.currentThread();
                                        dataSet.setPermissions(permissionRepository.findAll());
                                    }
            }, Executors.newVirtualThreadPerTaskExecutor());

            CompletableFuture.allOf(usersFuture, groupsFuture, rolesFuture, permissionsFuture)
                    .join();

            if (plan.needsRelationships()) {
                handleRelationships(plan, dataSet);
            }

            return dataSet;

        } catch (Exception e) {
            log.error("IAM 데이터 수집 실패", e);
            dataSet.setError("IAM 데이터 수집 중 오류 발생: " + e.getMessage());
            return dataSet;
        }
    }

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
            }
}