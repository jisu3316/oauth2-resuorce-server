package io.security.oauth2.springsecurityoauth2.configs;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;
import java.util.stream.Collectors;

public class CustomRoleConvert implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final String PREFIX = "ROLE_";
    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        String scopes = jwt.getClaimAsString("scope");
        Map<String, Object> realm_access = jwt.getClaimAsMap("realm_access");

        if (scopes == null || realm_access == null) {
            return Collections.EMPTY_LIST;
        }

        Collection<GrantedAuthority> authorities1 = Arrays.stream(scopes.split(" "))
                .map(roleName -> PREFIX + roleName)// 권한 프리픽스도 변경할 수 있다. SCOPE_가 아닌 ROLE_로 변경한다:
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        Collection<GrantedAuthority> authorities2 = ((List<String>) realm_access.get("roles"))
                .stream().map(roleName -> PREFIX + roleName)// 권한 프리픽스도 변경할 수 있다. SCOPE_가 아닌 ROLE_로 변경한다:
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        authorities1.addAll(authorities2);
        return authorities1;
    }
}
