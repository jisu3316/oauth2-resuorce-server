package io.security.oauth2.springsecurityoauth2.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class OAuth2ResourceServer2 {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new CustomRoleConvert());
        http.authorizeRequests(
                (requests) -> requests
                        .antMatchers("/photos/1").hasAnyAuthority("ROLE_photo")
                        .antMatchers("/photos/3").hasAnyAuthority("ROLE_default-roles-oauth2")
                        .anyRequest().authenticated());
        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter);
        return http.build();
    }

    @Bean
    SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
        http.antMatcher("/photos/2").authorizeRequests(
                (requests) -> requests.antMatchers("/photos/2").permitAll()
                        .anyRequest().authenticated());
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }
}
