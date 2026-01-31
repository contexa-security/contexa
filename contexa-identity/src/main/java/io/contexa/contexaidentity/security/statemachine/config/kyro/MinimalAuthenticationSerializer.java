package io.contexa.contexaidentity.security.statemachine.config.kyro;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.Serializer;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

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
        List<String> authorityStrings = authorities != null
                ? authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList()
                : new ArrayList<>();

        output.writeInt(authorityStrings.size());
        for (String authority : authorityStrings) {
            output.writeString(authority);
        }
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

        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }
}
