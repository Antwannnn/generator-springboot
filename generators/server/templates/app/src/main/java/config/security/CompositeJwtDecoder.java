package <%= packageName %>.config.security;

import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Component
public class CompositeJwtDecoder implements JwtDecoder {

    private final NimbusJwtDecoder idpDecoder;
    private final JwtTokenProvider localTokenProvider;

    public CompositeJwtDecoder(
            JwtTokenProvider localTokenProvider,
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri
    ) {
        this.localTokenProvider = localTokenProvider;
        this.idpDecoder = JwtDecoders.fromIssuerLocation(issuerUri);
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            String[] parts = token.split("\\.");
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
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
                return idpDecoder.decode(token);
            }

        } catch (Exception e) {
            throw new JwtException("Token decoding failed: " + e.getMessage(), e);
        }
    }
}
