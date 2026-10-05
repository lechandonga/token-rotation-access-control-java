package com.github.lechandonga.tokenrotationaccesscontroljava.token;

public record RefreshToken(
        String tokenId,
        String subject,
        String familyId,
        String keyId,
        long issuedAtEpochMilli,
        long expiresAtEpochMilli) {

    public boolean expiredAt(long nowEpochMilli) {
        return nowEpochMilli >= expiresAtEpochMilli;
    }
}
