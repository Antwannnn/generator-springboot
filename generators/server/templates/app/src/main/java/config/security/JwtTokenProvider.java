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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Date;

@Component
public class JwtTokenProvider {

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

    public String generateToken(Authentication authentication) {
        try {
            UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
            Date expiryDate = new Date(System.currentTimeMillis() + jwtExpirationInMs);

            // Create JWT claims
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(userPrincipal.getUsername())
                    .issuer(getLocalIssuerUri())
                    .audience(getLocalIssuerUri())
                    .issueTime(new Date())
                    .expirationTime(expiryDate)
                    .claim("authorities", userPrincipal.getAuthorities())
                    .build();

            // Create signed JWT
            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader(JWSAlgorithm.HS256),
                    claimsSet
            );

            // Sign the JWT
            JWSSigner signer = new MACSigner(jwtSecret);
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Error generating JWT token", e);
        }
    }

    public String getUsernameFromToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            return claimsSet.getSubject();
        } catch (ParseException e) {
            throw new RuntimeException("Error parsing JWT token", e);
        }
    }

    public boolean validateToken(String authToken) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(authToken);
            JWSVerifier verifier = new MACVerifier(jwtSecret);
            return signedJWT.verify(verifier);
        } catch (Exception e) {
            return false;
        }
    }

<%_ if (authenticationTypes.includes('jwt') && authenticationTypes.includes('oauth2-resource')) { _%>
    public String getIssuer(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getIssuer();
        } catch (ParseException e) {
            throw new RuntimeException("Error extracting issuer from token", e);
        }
    }

    public String getLocalIssuerUri() {
        return localIssuerUri + ":" + localPort;
    }
<%_ } _%>
}