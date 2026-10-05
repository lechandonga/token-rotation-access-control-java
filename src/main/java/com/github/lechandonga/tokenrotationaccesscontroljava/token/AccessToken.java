package com.github.lechandonga.tokenrotationaccesscontroljava.token;

import java.util.List;

public record AccessToken(
        String tokenId,
        String subject,
        List<String> scopes,
        String familyId,
        String keyId,
        long issuedAtEpochMilli,
        long expiresAtEpochMilli) {

    public boolean expiredAt(long nowEpochMilli) {
        return nowEpochMilli >= expiresAtEpochMilli;
    }
}
