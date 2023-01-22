package io.security.oauth2.springsecurityoauth2.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index() { return "index"; }

    @GetMapping("/api/user")
    public Authentication user(Authentication authentication, @AuthenticationPrincipal Jwt principal) throws URISyntaxException {

        JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) authentication;
        String sub = (String) authenticationToken.getTokenAttributes().get("sub");
        String email = (String) authenticationToken.getTokenAttributes().get("email");
        String scope = (String) authenticationToken.getTokenAttributes().get("scope");

        String sub1 = principal.getClaim("sub");
        String sub2 = (String) principal.getClaims().get("sub");
        String token = principal.getTokenValue();

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Authorization", "Bearer " + token);
        RequestEntity<String> request = new RequestEntity<>(httpHeaders, HttpMethod.GET, new URI("http://localhost:8080"));
        ResponseEntity<String> response = restTemplate.exchange(request, String.class);
        String body = response.getBody();

        return authentication;
    }
}
