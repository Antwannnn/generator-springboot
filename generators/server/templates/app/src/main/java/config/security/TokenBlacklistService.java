package <%= packageName %>.config.security;

import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TokenBlacklistService {

    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();

    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
    }

    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }

    public void removeTokenFromBlacklist(String token) {
        blacklistedTokens.remove(token);
    }

    public void clearBlacklist() {
        blacklistedTokens.clear();
    }
}
