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
import sonia.scm.security.AllowAnonymousAccess;
import sonia.scm.web.VndMediaType;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

@Path("v2/ces/serviceaccount")
@AllowAnonymousAccess
public class ServiceAccountResource {

  static final String SERVICE_ACCOUNT = VndMediaType.PREFIX + "serviceaccount" + VndMediaType.SUFFIX;

  private final CesAccessValidator accessValidator;
  private final ServiceAccountService serviceAccountService;

  @Inject
  public ServiceAccountResource(CesAccessValidator accessValidator, ServiceAccountService serviceAccountService) {
    this.accessValidator = accessValidator;
    this.serviceAccountService = serviceAccountService;
  }

  @POST
  @Consumes(SERVICE_ACCOUNT)
  public Response createServiceAccount(@Context HttpServletRequest request,
                           @HeaderParam("X-CES-Token") String apiToken,
                           @Valid UserCreateDto userCreate) {
    verifyAuthentication(request, apiToken);
    String username = userCreate.getUsername();
    String permission = userCreate.getPermission();
    String password = userCreate.getPassword();
    serviceAccountService.createUser(username, password, permission);
    return Response.created(null).build();
  }

  private void verifyAuthentication(HttpServletRequest request, String apiToken) {
    String remoteAddr = request.getRemoteAddr();
    if (!remoteAddr.equals("127.0.0.1")) {
      throw new AuthenticationException();
    }
    accessValidator.checkToken(apiToken);
  }
}
