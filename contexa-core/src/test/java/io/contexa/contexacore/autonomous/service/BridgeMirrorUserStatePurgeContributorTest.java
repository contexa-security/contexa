package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class BridgeMirrorUserStatePurgeContributorTest {

    private final List<String> calls = new ArrayList<>();

    @Test
    void theMirrorsOfTheDeletedPrincipalAreRemovedProfileAndPermissionsFirstInOneTransaction() {
        Users first = mirror(41L);
        Users second = mirror(42L);
        BridgeMirrorUserStatePurgeContributor contributor = contributor(Map.of("v0123456789ab-eng-k",
                List.of(first, second)));

        contributor.purge("v0123456789ab-eng-k");

        assertThat(contributor.name()).isEqualTo("bridge-mirror-users");
        assertThat(calls).containsExactly("begin", "find v0123456789ab-eng-k",
                "permissions 41", "profile 41", "user 41",
                "permissions 42", "profile 42", "user 42", "commit");
    }

    @Test
    void aPrincipalWithoutMirrorsLeavesEveryOtherUserAlone() {
        BridgeMirrorUserStatePurgeContributor contributor = contributor(Map.of("someone-else", List.of(mirror(7L))));

        contributor.purge("v0123456789ab-eng-k");
        contributor.purge(" ");

        assertThat(calls).containsExactly("begin", "find v0123456789ab-eng-k", "commit");
    }

    private BridgeMirrorUserStatePurgeContributor contributor(Map<String, List<Users>> mirrors) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("users", proxy(UserRepository.class, (method, args) -> switch (method) {
            case "findByExternalSubjectIdAndBridgeManagedTrue" -> {
                calls.add("find " + args[0]);
                yield mirrors.getOrDefault((String) args[0], List.of());
            }
            case "deleteById" -> {
                calls.add("user " + args[0]);
                yield null;
            }
            default -> throw new UnsupportedOperationException(method);
        }));
        beans.addBean("profiles", proxy(BridgeUserProfileRepository.class, (method, args) -> switch (method) {
            case "existsById" -> true;
            case "deleteById" -> {
                calls.add("profile " + args[0]);
                yield null;
            }
            default -> throw new UnsupportedOperationException(method);
        }));
        beans.addBean("permissions", proxy(UserRolePermissionRepository.class, (method, args) -> {
            if ("deleteByUserId".equals(method)) {
                calls.add("permissions " + args[0]);
                return null;
            }
            throw new UnsupportedOperationException(method);
        }));
        beans.addBean("transactions", new RecordingTransactionManager());
        return new BridgeMirrorUserStatePurgeContributor(beans.getBeanProvider(UserRepository.class),
                beans.getBeanProvider(BridgeUserProfileRepository.class),
                beans.getBeanProvider(UserRolePermissionRepository.class),
                beans.getBeanProvider(PlatformTransactionManager.class));
    }

    private static Users mirror(Long id) {
        Users user = new Users();
        user.setId(id);
        return user;
    }

    @FunctionalInterface
    private interface Handler {
        Object handle(String method, Object[] args);
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, Handler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (proxy, method, args) -> handler.handle(method.getName(), args));
    }

    private final class RecordingTransactionManager implements PlatformTransactionManager {

        @Override
        public TransactionStatus getTransaction(TransactionDefinition definition) {
            calls.add("begin");
            return new SimpleTransactionStatus();
        }

        @Override
        public void commit(TransactionStatus status) {
            calls.add("commit");
        }

        @Override
        public void rollback(TransactionStatus status) {
            calls.add("rollback");
        }
    }
}
