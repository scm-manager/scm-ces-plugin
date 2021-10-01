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
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import static java.nio.charset.StandardCharsets.UTF_8;

@Singleton
class CesAccessValidator {

  private static final Logger LOG = LoggerFactory.getLogger(CesAccessValidator.class);

  private final Runtime runtime;
  private final String configurationKey;

  private String apiToken;

  CesAccessValidator() {
    this(Runtime.getRuntime(), getConfigurationKey());
  }

  private static String getConfigurationKey() {
    String configurationKey = System.getenv("CES_TOKEN_CONFIGURATION_KEY");
    if (configurationKey == null) {
      LOG.error("Could not read name of configuration key for token from environment");
    }
    return configurationKey;
  }

  CesAccessValidator(Runtime runtime, String configurationKey) {
    this.runtime = runtime;
    this.configurationKey = configurationKey;
  }

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
    if (configurationKey == null) {
      LOG.error("Could not read name of configuration key for token from environment");
      return;
    }
    readToken(configurationKey);
  }

  private void readToken(String configurationKey) {
    try {
      LOG.info("Reading ces serviceaccount access token from doguctl with configuration key {}", configurationKey);
      Process process = runtime.exec(new String[]{"doguctl", "config", "--encrypted", configurationKey});
      LOG.trace("Started process");
      process.getOutputStream().close();
      LOG.trace("Closed out");
      InputStream inputStream = process.getInputStream();
      LOG.trace("Got input");
      String processOut = new BufferedReader(new InputStreamReader(inputStream, UTF_8)).readLine();
      int exitValue = process.waitFor();
      if (exitValue == 0) {
        apiToken = processOut;
        LOG.info("Found ces serviceaccount access token");
      } else {
        LOG.error("got non-zero exit value ({}) from doguctl call", exitValue);
      }
    } catch (Exception e) {
      LOG.error("Could not read token from doguctl", e);
    }
  }
}
