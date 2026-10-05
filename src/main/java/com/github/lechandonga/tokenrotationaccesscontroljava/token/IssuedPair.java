package com.github.lechandonga.tokenrotationaccesscontroljava.token;

public record IssuedPair(
        String accessToken,
        String refreshToken,
        AccessToken accessClaims,
        RefreshToken refreshClaims) {
}
