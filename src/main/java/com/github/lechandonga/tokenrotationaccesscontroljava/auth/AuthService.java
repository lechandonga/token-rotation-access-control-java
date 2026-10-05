package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

import org.springframework.stereotype.Service;

/**
 * 登录与刷新编排：协调主体目录、访问凭证与刷新凭证族。
 */
@Service
public class AuthService {

    /** 一次签发/轮换返回的凭证对。 */
    public record TokenPair(String accessToken, String refreshToken, String tokenType,
                            String familyId, String keyId) {
    }

    private final PrincipalDirectory principalDirectory;
    private final RefreshTokenFamilyService familyService;
    private final AccessTokenService accessTokenService;

    public AuthService(PrincipalDirectory principalDirectory,
                       RefreshTokenFamilyService familyService,
                       AccessTokenService accessTokenService) {
        this.principalDirectory = principalDirectory;
        this.familyService = familyService;
        this.accessTokenService = accessTokenService;
    }

    public TokenPair login(String subjectId, String secret) {
        Principal principal = principalDirectory.authenticate(subjectId, secret)
                .orElseThrow(() -> new AuthException(AuthErrorCode.UNKNOWN_SUBJECT, "主体不存在或凭据错误"));
        RefreshTokenFamilyService.FamilyStart start = familyService.startFamily(principal.subjectId());
        String accessToken = accessTokenService.issue(principal, start.familyId());
        String keyId = accessTokenService.verify(accessToken).keyId();
        return new TokenPair(accessToken, start.refreshToken(), "Bearer", start.familyId(), keyId);
    }

    public TokenPair refresh(String refreshToken) {
        RefreshTokenFamilyService.RotationResult result = familyService.rotate(refreshToken);
        Principal principal = principalDirectory.find(result.subject())
                .orElseThrow(() -> new AuthException(AuthErrorCode.UNKNOWN_SUBJECT));
        String accessToken = accessTokenService.issue(principal, result.familyId());
        String keyId = accessTokenService.verify(accessToken).keyId();
        return new TokenPair(accessToken, result.newRefreshToken(), "Bearer", result.familyId(), keyId);
    }

}
