package io.contexa.contexaidentity.security.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PasskeyUserStatePurgeContributorTest {

    private final PublicKeyCredentialUserEntityRepository userEntities = mock(PublicKeyCredentialUserEntityRepository.class);
    private final UserCredentialRepository userCredentials = mock(UserCredentialRepository.class);

    @Test
    void deletesEveryCredentialAndTheUserEntityOfTheDeletedAccount() {
        Bytes entityId = Bytes.random();
        PublicKeyCredentialUserEntity entity = ImmutablePublicKeyCredentialUserEntity.builder()
                .id(entityId).name("alice").displayName("Alice").build();
        CredentialRecord first = mock(CredentialRecord.class);
        CredentialRecord second = mock(CredentialRecord.class);
        Bytes firstId = Bytes.random();
        Bytes secondId = Bytes.random();
        when(first.getCredentialId()).thenReturn(firstId);
        when(second.getCredentialId()).thenReturn(secondId);
        when(userEntities.findByUsername("alice")).thenReturn(entity);
        when(userCredentials.findByUserId(entityId)).thenReturn(List.of(first, second));

        contributor().purge("alice");

        verify(userCredentials).delete(firstId);
        verify(userCredentials).delete(secondId);
        verify(userEntities).delete(entityId);
    }

    @Test
    void anAccountWithoutPasskeysIsLeftAlone() {
        when(userEntities.findByUsername("bob")).thenReturn(null);

        contributor().purge("bob");

        verify(userEntities, never()).delete(any());
    }

    private PasskeyUserStatePurgeContributor contributor() {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("userEntities", userEntities);
        beans.addBean("userCredentials", userCredentials);
        ObjectProvider<PublicKeyCredentialUserEntityRepository> entities =
                beans.getBeanProvider(PublicKeyCredentialUserEntityRepository.class);
        ObjectProvider<UserCredentialRepository> credentials = beans.getBeanProvider(UserCredentialRepository.class);
        return new PasskeyUserStatePurgeContributor(entities, credentials);
    }
}
