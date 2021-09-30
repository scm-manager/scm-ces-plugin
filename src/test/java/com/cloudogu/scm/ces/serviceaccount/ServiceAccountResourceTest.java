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
import org.jboss.resteasy.mock.MockHttpResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.web.JsonMockHttpRequest;
import sonia.scm.web.RestDispatcher;

import javax.servlet.http.HttpServletRequest;
import java.net.URISyntaxException;

import static com.cloudogu.scm.ces.serviceaccount.ServiceAccountResource.SERVICE_ACCOUNT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ServiceAccountResourceTest {

  @Mock
  private CesAccessValidator accessValidator;
  @Mock
  private ServiceAccountService serviceAccountService;
  @Mock
  private HttpServletRequest servletRequest;

  @InjectMocks
  private ServiceAccountResource resource;

  private final RestDispatcher dispatcher = new RestDispatcher();
  private final MockHttpResponse response = new MockHttpResponse();

  @BeforeEach
  void mockDispatcher() {
    dispatcher.addSingletonResource(resource);
    dispatcher.putDefaultContextObject(HttpServletRequest.class, servletRequest);

  }

  @Test
  void shouldCreateAccount() throws URISyntaxException {
    JsonMockHttpRequest request = JsonMockHttpRequest.post("/v2/ces/serviceaccount")
      .contentType(SERVICE_ACCOUNT)
      .json("{'username':'marvin','password':'boring','permission':'*'}");
    when(servletRequest.getRemoteAddr()).thenReturn("127.0.0.1");

    dispatcher.invoke(request, response);

    assertThat(response.getStatus()).isEqualTo(201);
    verify(serviceAccountService).createUser("marvin", "boring", "*");
  }

  @Test
  void shouldCheckToken() throws URISyntaxException {
    JsonMockHttpRequest request = JsonMockHttpRequest.post("/v2/ces/serviceaccount")
      .contentType(SERVICE_ACCOUNT)
      .header("X-CES-Token", "conquer-the-world")
      .json("{'username':'marvin','password':'boring','permission':'*'}");
    when(servletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
    doThrow(AuthenticationException.class).when(accessValidator).checkToken("conquer-the-world");

    dispatcher.invoke(request, response);

    assertThat(response.getStatus()).isEqualTo(401);
    verify(serviceAccountService, never()).createUser(anyString(), anyString(), anyString());
  }

  @Test
  void shouldRejectRequestsFromOtherClients() throws URISyntaxException {
    JsonMockHttpRequest request = JsonMockHttpRequest.post("/v2/ces/serviceaccount")
      .contentType(SERVICE_ACCOUNT)
      .json("{'username':'marvin','password':'boring','permission':'*'}");
    when(servletRequest.getRemoteAddr()).thenReturn("192.168.2.1");

    dispatcher.invoke(request, response);

    assertThat(response.getStatus()).isEqualTo(401);
    verify(serviceAccountService, never()).createUser(anyString(), anyString(), anyString());
  }
}
