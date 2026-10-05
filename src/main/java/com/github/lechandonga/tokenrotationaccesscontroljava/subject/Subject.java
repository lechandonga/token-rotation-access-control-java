package com.github.lechandonga.tokenrotationaccesscontroljava.subject;

import java.util.List;

public record Subject(String subjectId, String displayName, List<String> scopes) {
}
