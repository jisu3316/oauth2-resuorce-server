package io.security.oauth2.springsecurityoauth2.filter.authorization;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

//토큰 검증 필터
// OncePerRequestFilter : 여러번의 요청에도 한번만 응답하는 필터
public class JwtAuthorizationMacFilter extends JwtAuthorizationFilter {

    //이 필터는 공통클래스가아니고  MAC검증만하는 필터이므로 JWK로 안받아도된다.
    public JwtAuthorizationMacFilter(JWSVerifier jwsVerifier) {
        super(jwsVerifier);
    }

//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        String header = request.getHeader("Authorization");
//        if (header == null || !header.startsWith("Bearer ")) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        String token = header.replace("Bearer ", "");
//
//        SignedJWT signedJWT;
//        try {
//            signedJWT = SignedJWT.parse(token);
//            MACVerifier macVerifier = new MACVerifier(jwk.toSecretKey());
//            boolean verify = signedJWT.verify(macVerifier);
//
//            if (verify) {
//                JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
//                String username = jwtClaimsSet.getClaim("username").toString();
//                List<String> authority = (List) jwtClaimsSet.getClaim("authority");
//
//                if (username != null) {
//                    UserDetails user = User.withUsername(username)
//                            .password(UUID.randomUUID().toString())
//                            .authorities(authority.get(0))
//                            .build();
//                    Authentication authentication =
//                            new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
//                    SecurityContextHolder.getContext().setAuthentication(authentication);
//                }
//            }
//
//        } catch (Exception e) {
//            e.getStackTrace();
//        }
//        filterChain.doFilter(request, response);
//    }
}
