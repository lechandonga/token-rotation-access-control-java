package com.github.lechandonga.tokenrotationaccesscontroljava.web;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthContextHolder;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.RequireScope;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.TokenService;
import com.github.lechandonga.tokenrotationaccesscontroljava.token.AccessToken;
import com.github.lechandonga.tokenrotationaccesscontroljava.token.IssuedPair;
import com.github.lechandonga.tokenrotationaccesscontroljava.token.RefreshToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    /** 模拟登录：无真实密码，凭主体标识签发首个令牌族。 */
    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request) {
        IssuedPair pair = tokenService.issue(request.subjectId());
        return TokenResponse.from(pair);
    }

    /** 使用刷新凭证轮换：成功后旧刷新凭证立即失效。 */
    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request) {
        IssuedPair pair = tokenService.rotate(request.refreshToken());
        return TokenResponse.from(pair);
    }

    /** 显式吊销当前访问凭证所属的整个令牌族。 */
    @PostMapping("/revoke")
    @RequireScope("profile:read")
    public RevokeResponse revoke() {
        String familyId = AuthContextHolder.get().familyId();
        tokenService.revokeFamily(familyId);
        return new RevokeResponse(familyId, "REVOKED");
    }

    public record LoginRequest(String subjectId) {
    }

    public record RefreshRequest(String refreshToken) {
    }

    public record RevokeResponse(String familyId, String state) {
    }

    public record TokenResponse(String accessToken, String refreshToken, Claims claims) {
        static TokenResponse from(IssuedPair pair) {
            return new TokenResponse(pair.accessToken(), pair.refreshToken(), Claims.from(
                    pair.accessClaims(), pair.refreshClaims()));
        }

        public record Claims(
                String subject,
                java.util.List<String> scopes,
                String familyId,
                String accessTokenId,
                String refreshTokenId,
                String keyId,
                long accessExpiresAtEpochMilli,
                long refreshExpiresAtEpochMilli) {

            static Claims from(AccessToken access, RefreshToken refresh) {
                return new Claims(access.subject(), access.scopes(), access.familyId(),
                        access.tokenId(), refresh.tokenId(), access.keyId(),
                        access.expiresAtEpochMilli(), refresh.expiresAtEpochMilli());
            }
        }
    }
}
