package io.security.oauth2.springsecurityoauth2.configs;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.security.oauth2.springsecurityoauth2.siganture.MacSecuritySigner;
import io.security.oauth2.springsecurityoauth2.siganture.RsaSecuritySigner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SignatureConfig {

    @Bean
    public MacSecuritySigner securitySigner() {
        return new MacSecuritySigner();
    }

    @Bean
    public OctetSequenceKey octetSequenceKey() throws JOSEException {
        OctetSequenceKey octetSequenceKey = new OctetSequenceKeyGenerator(256)
                .keyID("macKey")
                .algorithm(JWSAlgorithm.HS256)
                .generate();
        return octetSequenceKey;
    }

    @Bean
    public RsaSecuritySigner rsaSecuritySigner() {
        return new RsaSecuritySigner();
    }

    //jwt-decoder 설정 시 yml의 값이 바뀌면 여기 값도 바뀌어야 한다.
    @Bean
    public RSAKey rsaKey() throws JOSEException {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID("rsaKey")
                .algorithm(JWSAlgorithm.RS512)
                .generate();
        return rsaKey;
    }
}
