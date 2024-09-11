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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CesTokenGeneratorTest {

  @Mock
  private HttpServletRequest request;

  @Test
  void shouldCreateToken() {
    CesTokenGenerator cesTokenGenerator = new CesTokenGenerator("X-CES-Token");
    when(request.getHeader("X-CES-Token")).thenReturn("secret");
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");

    CesToken token = cesTokenGenerator.createToken(request);

    assertThat(token.getRemoteAddress()).isEqualTo("127.0.0.1");
    assertThat(token.getCredentials()).isEqualTo("secret");
  }

  @Test
  void shouldFailIfHeaderNameNotDefined() {
    CesTokenGenerator cesTokenGenerator = new CesTokenGenerator(null);

    CesToken token = cesTokenGenerator.createToken(request);

    assertThat(token).isNull();
  }

  @Test
  void shouldFailIfHeaderNotSet() {
    CesTokenGenerator cesTokenGenerator = new CesTokenGenerator("X-CES-Token");

    CesToken token = cesTokenGenerator.createToken(request);

    assertThat(token).isNull();
  }
}
