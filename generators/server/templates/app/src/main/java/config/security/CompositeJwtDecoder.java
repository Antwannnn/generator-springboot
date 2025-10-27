package <%= packageName %>.config.security;

import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Component
public class CompositeJwtDecoder implements JwtDecoder {

    private final NimbusJwtDecoder idpDecoder;
    private final JwtTokenProvider localTokenProvider;
<%_ if (authenticationTypes.includes('jwt') && !authenticationTypes.includes('oauth2-resource')) { _%>
    private final boolean oauth2ResourceEnabled = false;
<%_ } else { _%>
    private final boolean oauth2ResourceEnabled = true;
<%_ } _%>

<%_ if (authenticationTypes.includes('jwt')) { _%>
    @Autowired
    private TokenBlacklistService tokenBlacklistService;
<%_ } _%>

    public CompositeJwtDecoder(
            JwtTokenProvider localTokenProvider<%_ if (authenticationTypes.includes('oauth2-resource')) { _%>,
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri<%_ } _%>
    ) {
        this.localTokenProvider = localTokenProvider;
<%_ if (authenticationTypes.includes('oauth2-resource')) { _%>
        this.idpDecoder = JwtDecoders.fromIssuerLocation(issuerUri);
<%_ } else { _%>
        this.idpDecoder = null;
<%_ } _%>
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            String[] parts = token.split("\\.");
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
            
<%_ if (authenticationTypes.includes('jwt')) { _%>
            // Check if token is blacklisted
            if(tokenBlacklistService.isTokenBlacklisted(token)){
                throw new JwtException("Token has been revoked");
            }
<%_ } _%>
            
            // Check if it's a local JWT token
            if (payloadJson.contains("\"iss\":\"" + localTokenProvider.getLocalIssuerUri() + "\"")) {
                if (!localTokenProvider.validateToken(token)) {
                    throw new JwtException("Invalid local JWT signature");
                }

                SignedJWT signedJWT = SignedJWT.parse(token);
                Map<String, Object> claims = signedJWT.getJWTClaimsSet().getClaims();

                return Jwt.withTokenValue(token)
                        .headers(h -> h.put("alg", "HS256"))
                        .claims(c -> {
                            claims.forEach((k, v) -> {
                                if (v instanceof Date date) {
                                    c.put(k, date.toInstant());
                                } else {
                                    c.put(k, v);
                                }
                            });
                        })
                        .build();
            } else {
                // For OAuth2-resource case, decode external token
                if (oauth2ResourceEnabled && idpDecoder != null) {
                    return idpDecoder.decode(token);
                } else {
                    // JWT-only case: all tokens should be local
                    throw new JwtException("Invalid token issuer for JWT-only configuration");
                }
            }

        } catch (Exception e) {
            throw new JwtException("Token decoding failed: " + e.getMessage(), e);
        }
    }
}
