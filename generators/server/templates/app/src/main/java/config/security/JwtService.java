package <%= packageName %>.config.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;

@Service
public class JwtService {

    @Value("${app.security.jwt.secret}")
    private String jwtSecret;

    @Value("${app.security.jwt.expiration}")
    private int jwtExpirationInMs;

<%_ if (authenticationTypes.includes('jwt') && authenticationTypes.includes('oauth2-resource')) { _%>
    @Value("${server.uri}")
    private String localIssuerUri;

    @Value("${server.port}")
    private int localPort;
<%_ } _%>

    private JWSSigner getSigner() throws JOSEException {
        return new MACSigner(java.util.Base64.getDecoder().decode(jwtSecret));
    }

    private JWSVerifier getVerifier() throws JOSEException {
        return new MACVerifier(java.util.Base64.getDecoder().decode(jwtSecret));
    }

    // --- Génération Access Token ---
    public String generateAccessToken(String username) throws JOSEException {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(username)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(15 * 60))) // 15 min
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.HS256),
                claims
        );
        signedJWT.sign(getSigner());
        return signedJWT.serialize();
    }

    // --- Génération Refresh Token ---
    public String generateRefreshToken(String username) throws JOSEException {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(username)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(7 * 24 * 60 * 60))) // 7 jours
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.HS256),
                claims
        );
        signedJWT.sign(getSigner());
        return signedJWT.serialize();
    }

    // --- Validation Token ---
    public boolean validateToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            if (!signedJWT.verify(getVerifier())) return false;
            Date exp = signedJWT.getJWTClaimsSet().getExpirationTime();
            return exp.after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    // --- Extraction Username ---
    public String extractUsername(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getSubject();
        } catch (ParseException e) {
            return null;
        }
    }
<%_ if (authenticationTypes.includes('jwt') && authenticationTypes.includes('oauth2-resource')) { _%>

    public String getLocalIssuerUri() {
        return localIssuerUri + ":" + localPort;
    }
<%_ } _%>
}