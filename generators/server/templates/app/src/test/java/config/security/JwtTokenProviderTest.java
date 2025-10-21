package <%= packageName %>.config.security;

<%_ if (authenticationType === 'jwt') { _%>
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.TestPropertySource;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(properties = {
    "app.security.jwt.secret=mySecretKey",
    "app.security.jwt.expiration=86400000"
})
class JwtTokenProviderTest {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Test
    void testGenerateToken() {
        UserDetails userDetails = new User("testuser", "password", Collections.emptyList());
        Authentication authentication = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
            userDetails, null, userDetails.getAuthorities());

        String token = tokenProvider.generateToken(authentication);
        
        assertNotNull(token);
        assertTrue(tokenProvider.validateToken(token));
    }

    @Test
    void testGetUsernameFromToken() {
        UserDetails userDetails = new User("testuser", "password", Collections.emptyList());
        Authentication authentication = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
            userDetails, null, userDetails.getAuthorities());

        String token = tokenProvider.generateToken(authentication);
        String username = tokenProvider.getUsernameFromToken(token);
        
        assertEquals("testuser", username);
    }

    @Test
    void testValidateToken() {
        UserDetails userDetails = new User("testuser", "password", Collections.emptyList());
        Authentication authentication = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
            userDetails, null, userDetails.getAuthorities());

        String token = tokenProvider.generateToken(authentication);
        
        assertTrue(tokenProvider.validateToken(token));
        assertFalse(tokenProvider.validateToken("invalid-token"));
    }
}
<%_ } _%>
