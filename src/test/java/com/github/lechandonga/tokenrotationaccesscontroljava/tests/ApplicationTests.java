package com.github.lechandonga.tokenrotationaccesscontroljava.tests;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.boot.test.context.SpringBootTest;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.Business;

/**
 * @author Vincent
 * @version 1.0
 */
@Business("工程上下文冒烟（原有测试保持通过）")
@SpringBootTest
public class ApplicationTests {
    @Test
    @DisplayName("Spring 应用上下文可以正常加载")
    public void contentLoad() {
    }
}
