/*
 * Copyright (c) 2020 - present Cloudogu GmbH
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/.
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
