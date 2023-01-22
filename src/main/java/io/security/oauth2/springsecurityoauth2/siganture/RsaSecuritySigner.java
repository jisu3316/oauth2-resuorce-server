package io.security.oauth2.springsecurityoauth2.siganture;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.security.core.userdetails.UserDetails;

//RSA 방식의 토큰을 서명하고 발행하는 역할을 한다.
public class RsaSecuritySigner extends SecuritySigner {

    @Override
    public String getJwtToken(UserDetails user, JWK jwk) throws JOSEException {

        RSASSASigner jwtSigner = new RSASSASigner(((RSAKey) jwk).toRSAPrivateKey());
        return super.getJwtTokenInternal(jwtSigner, user, jwk);
    }
}
