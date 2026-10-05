package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

import java.util.List;

public record AccessPrincipal(String subject, List<String> scopes, String tokenId, String familyId) {
}
