package io.security.oauth2.springsecurityoauth2.filter.authorization;

import com.nimbusds.jose.JWSVerifier;

//토큰 검증 필터
// OncePerRequestFilter : 여러번의 요청에도 한번만 응답하는 필터
public class JwtAuthorizationRsaFilter extends JwtAuthorizationFilter {

    //이 필터는 공통클래스가아니고  MAC검증만하는 필터이므로 JWK로 안받아도된다.
    public JwtAuthorizationRsaFilter(JWSVerifier jwsVerifier) {
        super(jwsVerifier);
    }

}
