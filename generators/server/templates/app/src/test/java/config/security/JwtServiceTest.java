package <%= packageName %>.config.security;

<%_ if (authenticationTypes && authenticationTypes.includes('jwt')) { _%>
import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(properties = {
    "app.security.jwt.secret=YS1zdHJpbmctc2VjcmV0LWF0LWxlYXN0LTI1Ni1iaXRzLWxvbmc=",
    "app.security.jwt.expiration=86400000"
})
class JwtServiceTest {

    @Autowired
    private JwtService jwtService;

    @Test
    void testGenerateAccessToken() throws JOSEException {
        String token = jwtService.generateAccessToken("testuser");
        
        assertNotNull(token);
        assertTrue(jwtService.validateToken(token));
    }

    @Test
    void testGenerateRefreshToken() throws JOSEException {
        String token = jwtService.generateRefreshToken("testuser");
        
        assertNotNull(token);
        assertTrue(jwtService.validateToken(token));
    }

    @Test
    void testExtractUsername() throws JOSEException {
        String token = jwtService.generateAccessToken("testuser");
        String username = jwtService.extractUsername(token);
        
        assertEquals("testuser", username);
    }

    @Test
    void testValidateToken() throws JOSEException {
        String token = jwtService.generateAccessToken("testuser");
        
        assertTrue(jwtService.validateToken(token));
        assertFalse(jwtService.validateToken("invalid-token"));
    }
}
<%_ } _%>

