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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

@Singleton
public class CesAccessValidator {

  private static final Logger LOG = LoggerFactory.getLogger(CesAccessValidator.class);

  private String apiToken;

  void checkToken(String apiToken) {
    assertTokenRead();
    if (apiToken == null) {
      LOG.trace("No access token given; rejecting request");
      throw new AuthenticationException();
    }
    if (!this.apiToken.equals(apiToken)) {
      LOG.trace("Given access token does not match configured token; rejecting request");
      throw new AuthenticationException();
    }
    LOG.trace("Given access token ok; granting access");
  }

  private synchronized void assertTokenRead() {
    if (apiToken == null) {
      readToken();
      if (apiToken == null) {
        throw new AuthenticationException();
      }
    }
  }

  private void readToken() {
    try {
      LOG.info("Reading ces serviceaccount access token from doguctl");
      Process process = Runtime.getRuntime().exec(new String[]{"doguctl", "config", "--encrypted", "serviceaccount_token"});
      InputStream inputStream = process.getInputStream();
      apiToken = new Scanner(inputStream, "UTF-8").nextLine();
      LOG.info("Found ces serviceaccount access token");
    } catch (IOException e) {
      LOG.error("Could not read token from doguctl", e);
    }
  }
}
