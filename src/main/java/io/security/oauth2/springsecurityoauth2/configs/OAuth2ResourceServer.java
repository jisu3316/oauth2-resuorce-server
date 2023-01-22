//package io.security.oauth2.springsecurityoauth2.configs;
//
//import com.nimbusds.jose.JOSEException;
//import com.nimbusds.jose.crypto.MACVerifier;
//import com.nimbusds.jose.crypto.RSASSAVerifier;
//import com.nimbusds.jose.jwk.OctetSequenceKey;
//import com.nimbusds.jose.jwk.RSAKey;
//import io.security.oauth2.springsecurityoauth2.filter.authentication.JwtAuthenticationFilter;
//import io.security.oauth2.springsecurityoauth2.filter.authorization.JwtAuthorizationMacFilter;
//import io.security.oauth2.springsecurityoauth2.filter.authorization.JwtAuthorizationRsaFilter;
//import io.security.oauth2.springsecurityoauth2.siganture.MacSecuritySigner;
//import io.security.oauth2.springsecurityoauth2.siganture.RsaSecuritySigner;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.password.NoOpPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//
//import javax.servlet.Filter;
//
////RSA, MAC 기반 토큰 검증 필터체인
//@Configuration
//public class OAuth2ResourceServer {
//
//    // bean 등록으로 인해 필요가 없어졌다.
////    private final MacSecuritySigner macSecuritySigner;
////    private final OctetSequenceKey octetSequenceKey;
//
////    public OAuth2ResourceServer(MacSecuritySigner macSecuritySigner, OctetSequenceKey octetSequenceKey) {
////        this.macSecuritySigner = macSecuritySigner;
////        this.octetSequenceKey = octetSequenceKey;
////    }
//
//    @Bean
//    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        //리소스 서버는 사용자의 액세스 토큰을 가지고 검증을 하기 때문에 csrf토큰을 비활성화하는것이 맞다.
//        http.csrf().disable();
//        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//        http.authorizeRequests((requests) -> requests.antMatchers("/").permitAll()
//                .anyRequest().authenticated());
//        http.userDetailsService(userDetailsService());
//
//        // MAC 방식 토큰 발행
////        http.addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class);
//        // MAC 방식 필터 기반 검증 방법
////        http.addFilterBefore(jwtAuthorizationMacFilter(null), UsernamePasswordAuthenticationFilter.class);
//
//        // MAC 방식 jwtDecoder 에 의한 검증 방법
////        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//
//        //RSA 방식 토큰 발행
////        http.addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class);
//        // RSA 방식 필터에 기반 검증 방법
////        http.addFilterBefore(jwtAuthorizationRsaFilter(null), UsernamePasswordAuthenticationFilter.class);
//
//        //RSA jwt Decoder 에 의한 검증 방법
////        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//
//        //setURI 에 의 한 검증 방법
//        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//        return http.build();
//    }
//
//    //MAC 필터 기반 검증방법
////    @Bean
////    public JwtAuthorizationMacFilter jwtAuthorizationMacFilter(OctetSequenceKey octetSequenceKey) throws JOSEException {
////        return new JwtAuthorizationMacFilter(new MACVerifier(octetSequenceKey.toSecretKey()));
////    }
//
//
//    //MAC 필터 기반 방식 토큰 발행
////    @Bean
////    public JwtAuthenticationFilter jwtAuthenticationFilter(MacSecuritySigner macSecuritySigner, OctetSequenceKey octetSequenceKey) throws Exception {
////        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(macSecuritySigner, octetSequenceKey);
////        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
////        return jwtAuthenticationFilter;
////    }
//
//
//    // RSA 필터 기반 검증방법 비 대칭키 방식이므로 퍼블릭키로 토큰을 검증한다.
////    @Bean
////    public JwtAuthorizationRsaFilter jwtAuthorizationRsaFilter(RSAKey rsaKey) throws JOSEException {
////        return new JwtAuthorizationRsaFilter(new RSASSAVerifier(rsaKey.toRSAPublicKey()));
////    }
//
//   //RSA 필터 기반 방식 토큰 발행
////    @Bean
////    public JwtAuthenticationFilter jwtAuthenticationFilter(RsaSecuritySigner rsaSecuritySigner, RSAKey rsaKey) throws Exception {
////        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(rsaSecuritySigner, rsaKey);
////        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
////        return jwtAuthenticationFilter;
////    }
//
//
//    //인증해주는 곳 얘가 없으면 JwtAuthenticationFilter 생성을 못한다.
////    @Bean
////    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
////        return authenticationConfiguration.getAuthenticationManager();
////    }
//
//    @Bean
//    public UserDetailsService userDetailsService() {
//
//        UserDetails user = User.withUsername("user").password("1234").authorities("ROLE_USER").build();
//        return new InMemoryUserDetailsManager(user);
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return NoOpPasswordEncoder.getInstance();
//    }
//}
