/*
 * MIT License
 *
 * Copyright (c) 2020-present Cloudogu GmbH and Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.cloudogu.scm.ces.serviceaccount;

import org.apache.shiro.authc.AuthenticationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CesAccessValidatorTest {

  @Mock
  private Runtime runtime;
  @Mock
  private Process process;

  private CesAccessValidator validator;

  @Test
  void shouldAlwaysFailIfConfigurationKeyIsUnknown() {
    validator = new CesAccessValidator(runtime, null);

    assertThrows(AuthenticationException.class,
      () -> validator.checkToken("valid"));
  }

  @Nested
  class ForFailingDoguctlCalls {

    @BeforeEach
    void initValidator() throws IOException {
      validator = new CesAccessValidator(runtime, "token");

      when(runtime.exec(new String[]{"doguctl", "config", "--encrypted", "token"}))
        .thenReturn(process);
      when(process.getOutputStream())
        .thenReturn(mock(OutputStream.class));
    }

    @Test
    void shouldAlwaysFailIfDoguctlExitsWithNonZero() throws InterruptedException {
      when(process.waitFor()).thenReturn(1);
      when(process.getInputStream())
        .thenReturn(new ByteArrayInputStream("no value provided for key 'token': no default value was provided".getBytes(StandardCharsets.UTF_8)));

      assertThrows(AuthenticationException.class,
        () -> validator.checkToken("valid"));
    }

    @Test
    void shouldAlwaysFailIfTokenCouldNotBeRead() {
      when(process.getInputStream())
        .thenThrow(RuntimeException.class);

      assertThrows(AuthenticationException.class,
        () -> validator.checkToken("valid"));
    }
  }

  @Nested
  class WithCorrectConfiguration {

    @BeforeEach
    void initValidator() throws IOException, InterruptedException {
      validator = new CesAccessValidator(runtime, "token");
      when(runtime.exec(new String[]{"doguctl", "config", "--encrypted", "token"}))
        .thenReturn(process);
      when(process.getInputStream())
        .thenReturn(new ByteArrayInputStream("valid".getBytes(StandardCharsets.UTF_8)));
      when(process.getOutputStream())
        .thenReturn(mock(OutputStream.class));
      when(process.waitFor()).thenReturn(0);
    }

    @Test
    void shouldPassWithCorrectToken() {
      validator.checkToken("valid");

      // test is ok, when we get no exception
    }

    @Test
    void shouldFailForInvalidToken() {
      assertThrows(AuthenticationException.class,
        () -> validator.checkToken("invalid"));
    }
  }
}
