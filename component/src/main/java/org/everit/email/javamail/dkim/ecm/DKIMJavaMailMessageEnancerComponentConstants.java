/*
 * Copyright (C) 2011 Everit Kft. (http://www.everit.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.everit.email.javamail.dkim.ecm;

/**
 * Constants for Message DKIMSigner Component.
 */
public final class DKIMJavaMailMessageEnancerComponentConstants {

  /**
   * References of the component.
   */
  public static final class References {

    public static final String SERVICE_REF_KEY_STORE = "keyStore";

    private References() {
    }
  }

  public static final String ATTR_ADDITIONAL_HEADERS = "additionalHeaders";

  public static final String ATTR_BODY_CANONICALIZATION = "bodyCanonicalization";

  public static final String ATTR_EXCLUDED_HEADERS = "excludedHeaders";

  public static final String ATTR_HEADER_CANONICALIZATION = "headerCanonicalization";

  public static final String ATTR_IDENTITY = "identity";

  public static final String ATTR_KEY_STORE = References.SERVICE_REF_KEY_STORE + ".target";

  public static final String ATTR_KEY_STORE_PASSWORD = "keyStorePassword";

  public static final String ATTR_PRIVATE_KEY_ALIAS = "privateKeyAlias";

  public static final String ATTR_SELECTOR = "selector";

  public static final String ATTR_SIGNING_ALGORITHM = "signingAlgorithm";

  public static final String ATTR_SIGNING_DOMAIN = "signingDomain";

  public static final String ATTR_USE_LENGTH_PARAM = "useLengthParam";

  public static final String ATTR_Z_PARAM = "zParam";

  public static final String CANONICALIZATION_RELAXED = "RELAXED";

  public static final String CANONICALIZATION_SIMPLE = "SIMPLE";

  public static final String SERVICE_PID =
      "org.everit.email.javamail.ecm.DKIMJavaMailMessageEnancer";

  public static final String SIGNING_ALGORITHM_SHA1_WITH_RSA = "SHA1_WITH_RSA";

  public static final String SIGNING_ALGORITHM_SHA256_WITH_RSA = "SHA256_WITH_RSA";

  private DKIMJavaMailMessageEnancerComponentConstants() {
  }
}
