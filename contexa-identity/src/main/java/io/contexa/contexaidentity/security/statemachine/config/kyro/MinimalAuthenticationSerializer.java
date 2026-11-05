/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.statemachine.config.kyro;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.Serializer;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import io.contexa.contexaidentity.security.handler.login.LoginFactsDetails;
import io.contexa.contexaidentity.security.handler.login.LoginFactsRecorder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * What a stored MFA flow keeps of a sign-in of any kind: its name, its authorities, whether it is authenticated and the
 * facts of its login. That is what the flow reads of it. The principal, the credentials and every other detail stay out:
 * they are the application's objects (its user, the token of an identity provider), which another node may not be able
 * to load or rebuild, and they hold what the store must not see (a password hash). The sign-in reads back as a
 * username and password token named after the user.
 */
public class MinimalAuthenticationSerializer extends Serializer<Authentication> {

    @Override
    public void write(Kryo kryo, Output output, Authentication authentication) {
        if (authentication == null) {
            output.writeBoolean(false);
            return;
        }
        output.writeBoolean(true);

        output.writeString(authentication.getName());

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        // An authority may state no text (GrantedAuthority allows it), and a simple authority cannot be made of none.
        List<String> authorityStrings = authorities != null
                ? authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .filter(StringUtils::hasText)
                    .toList()
                : new ArrayList<>();

        output.writeInt(authorityStrings.size());
        for (String authority : authorityStrings) {
            output.writeString(authority);
        }

        output.writeBoolean(authentication.isAuthenticated());
        LoginFactsDetails login = LoginFactsRecorder.loginOf(authentication, null, null);
        kryo.writeObjectOrNull(output, login != null ? login.withoutRequest() : null, LoginFactsDetails.class);
    }

    @Override
    public Authentication read(Kryo kryo, Input input, Class<? extends Authentication> type) {
        boolean exists = input.readBoolean();
        if (!exists) {
            return null;
        }

        String username = input.readString();

        int authorityCount = input.readInt();
        List<SimpleGrantedAuthority> authorities = new ArrayList<>(authorityCount);
        for (int i = 0; i < authorityCount; i++) {
            String authority = input.readString();
            authorities.add(new SimpleGrantedAuthority(authority));
        }

        boolean authenticated = input.readBoolean();
        LoginFactsDetails login = kryo.readObjectOrNull(input, LoginFactsDetails.class);

        UsernamePasswordAuthenticationToken restored = new UsernamePasswordAuthenticationToken(username, null, authorities);
        if (!authenticated) {
            restored.setAuthenticated(false);
        }
        restored.setDetails(login);
        return restored;
    }
}
