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
package org.everit.email.javamail.dkim.ecm.internal;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.Hashtable;

import org.everit.email.javamail.dkim.DKIMJavaMailMessageEnancer;
import org.everit.email.javamail.dkim.DKIMJavaMailMessageEnhancerConfig;
import org.everit.email.javamail.dkim.ecm.DKIMJavaMailMessageEnancerComponentConstants;
import org.everit.email.javamail.sender.JavaMailMessageEnhancer;
import org.everit.osgi.ecm.annotation.Activate;
import org.everit.osgi.ecm.annotation.Component;
import org.everit.osgi.ecm.annotation.ConfigurationPolicy;
import org.everit.osgi.ecm.annotation.Deactivate;
import org.everit.osgi.ecm.annotation.ManualService;
import org.everit.osgi.ecm.annotation.ServiceRef;
import org.everit.osgi.ecm.annotation.attribute.BooleanAttribute;
import org.everit.osgi.ecm.annotation.attribute.PasswordAttribute;
import org.everit.osgi.ecm.annotation.attribute.StringAttribute;
import org.everit.osgi.ecm.annotation.attribute.StringAttributeOption;
import org.everit.osgi.ecm.component.ComponentContext;
import org.everit.osgi.ecm.component.ConfigurationException;
import org.everit.osgi.ecm.extender.ECMExtenderConstants;
import org.osgi.framework.ServiceRegistration;

import aQute.bnd.annotation.headers.ProvideCapability;
import net.markenwerk.utils.mail.dkim.Canonicalization;
import net.markenwerk.utils.mail.dkim.SigningAlgorithm;

/**
 * A {@link JavaMailMessageEnhancer} that DKIM signing Java Mail Message.
 */
@Component(componentId = DKIMJavaMailMessageEnancerComponentConstants.SERVICE_PID,
    configurationPolicy = ConfigurationPolicy.FACTORY,
    label = "Everit Message DKIMSigner Component",
    description = "Java Mail Message enhancer implemantation that message sign with DKIM.")
@ProvideCapability(ns = ECMExtenderConstants.CAPABILITY_NS_COMPONENT,
    value = ECMExtenderConstants.CAPABILITY_ATTR_CLASS + "" + "=${@class}")
@ManualService({ JavaMailMessageEnhancer.class })
public class DKIMJavaMailMessageEnancerComponent {

  private final DKIMJavaMailMessageEnhancerConfig config = new DKIMJavaMailMessageEnhancerConfig();

  private KeyStore keyStore;

  private String keyStorePassword;

  private String privateKeyAlias;

  private ServiceRegistration<JavaMailMessageEnhancer> serviceRegistration;

  /**
   * Creates the {@link DKIMJavaMailMessageEnancer} and registers it as an OSGi service.
   *
   * @param componentContext
   *          The context of the component.
   */
  @Activate
  public void activate(
      final ComponentContext<DKIMJavaMailMessageEnancerComponent> componentContext) {

    config.privateKey(readPrivateKey());

    JavaMailMessageEnhancer messageDKIMSigner = new DKIMJavaMailMessageEnancer(config);
    Dictionary<String, ?> properties = new Hashtable<>(componentContext.getProperties());

    serviceRegistration = componentContext.registerService(JavaMailMessageEnhancer.class,
        messageDKIMSigner, properties);
  }

  /**
   * Component deactivator method that unregister service.
   */
  @Deactivate
  public void deactivate() {
    if (serviceRegistration != null) {
      serviceRegistration.unregister();
    }
  }

  private RSAPrivateKey readPrivateKey() {
    if (keyStore == null) {
      throw new ConfigurationException("Key store is null");
    }
    try {
      return (RSAPrivateKey) keyStore.getKey(privateKeyAlias, keyStorePassword.toCharArray());
    } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
      throw new ConfigurationException("Problem to get RSAPrivateKey");
    }

  }

  /**
   * Additional headers that should be signed if available. These headers are added to the ones
   * defined as default headers in DkimSigner class.
   *
   * @param additionalHeadersToSign
   *          An array of headers or <code>null</code>.
   */
  @StringAttribute(
      attributeId = DKIMJavaMailMessageEnancerComponentConstants.ATTR_ADDITIONAL_HEADERS,
      optional = true, label = "Addition headers to sign",
      description = "Additional headers that should be signed if available. These headers are"
          + " added to the ones defined as default headers in DkimSigner class.")
  public void setAdditionalHeadersToSign(final String[] additionalHeadersToSign) {
    if (additionalHeadersToSign == null) {
      config.additionalHeadersToSign = Collections.emptySet();
    } else {
      config.additionalHeadersToSign = new HashSet<>(Arrays.asList(additionalHeadersToSign));
    }
  }

  /**
   * Setter that accepts null.
   *
   * @param bodyCanonicalization
   *          The canonicalization or <code>null</code> for default value.
   */
  @StringAttribute(
      attributeId = DKIMJavaMailMessageEnancerComponentConstants.ATTR_BODY_CANONICALIZATION,
      label = "Body canonicalization",
      description = "The canonicalization to be used for the body. More information in RFC4871.",
      optional = true,
      options = {
          @StringAttributeOption(
              value = DKIMJavaMailMessageEnancerComponentConstants.CANONICALIZATION_SIMPLE,
              label = DKIMJavaMailMessageEnancerComponentConstants.CANONICALIZATION_SIMPLE),
          @StringAttributeOption(
              value = DKIMJavaMailMessageEnancerComponentConstants.CANONICALIZATION_RELAXED,
              label = DKIMJavaMailMessageEnancerComponentConstants.CANONICALIZATION_RELAXED)
      })
  public void setBodyCanonicalization(final String bodyCanonicalization) {
    if (bodyCanonicalization != null) {
      config.bodyCanonicalization = Canonicalization.valueOf(bodyCanonicalization);
    } else {
      config.bodyCanonicalization = null;
    }
  }

  /**
   * Headers that should be excluded from the signature. By default, the headers that are defined in
   * the DkimSigner class and the ones defined in additionalHeadersToSign configuration are used.
   *
   * @param excludedHeadersFromSign
   *          An array of headers or <code>null</code>.
   */
  @StringAttribute(
      attributeId = DKIMJavaMailMessageEnancerComponentConstants.ATTR_EXCLUDED_HEADERS,
      optional = true, label = "Addition headers to sign",
      description = "Headers that should be excluded from the signature. By default, the headers "
          + "that are defined in the DkimSigner class and the ones defined in "
          + "additionalHeadersToSign configuration are used.")
  public void setExcludedHeadersFromSign(final String[] excludedHeadersFromSign) {
    if (excludedHeadersFromSign == null) {
      config.excludedHeadersFromSign = Collections.emptySet();
    } else {
      config.excludedHeadersFromSign = new HashSet<>(Arrays.asList(excludedHeadersFromSign));
    }
  }

  /**
   * Setter that accepts null.
   *
   * @param headerCanonicalization
   *          The canonicalization or <code>null</code> for default value.
   */
  @StringAttribute(
      attributeId = DKIMJavaMailMessageEnancerComponentConstants.ATTR_HEADER_CANONICALIZATION,
      label = "Header canonicalization",
      description = "The canonicalization to be used for the header. More information in RFC4871.",
      optional = true,
      options = {
          @StringAttributeOption(
              value = DKIMJavaMailMessageEnancerComponentConstants.CANONICALIZATION_SIMPLE,
              label = DKIMJavaMailMessageEnancerComponentConstants.CANONICALIZATION_SIMPLE),
          @StringAttributeOption(
              value = DKIMJavaMailMessageEnancerComponentConstants.CANONICALIZATION_RELAXED,
              label = DKIMJavaMailMessageEnancerComponentConstants.CANONICALIZATION_RELAXED)
      })
  public void setHeaderCanonicalization(final String headerCanonicalization) {
    if (headerCanonicalization != null) {
      config.headerCanonicalization = Canonicalization.valueOf(headerCanonicalization);
    } else {
      config.headerCanonicalization = null;
    }
  }

  @StringAttribute(attributeId = DKIMJavaMailMessageEnancerComponentConstants.ATTR_IDENTITY,
      optional = true,
      label = "Identity",
      description = "Identity of the user or agent (e.g., a mailing list manager) "
          + "on behalf of which this message is signed. More information in RFC4871.")
  public void setIdentity(final String identity) {
    config.identity = identity;
  }

  @ServiceRef(attributeId = DKIMJavaMailMessageEnancerComponentConstants.ATTR_KEY_STORE,
      referenceId = DKIMJavaMailMessageEnancerComponentConstants.References.SERVICE_REF_KEY_STORE,
      label = "Key store",
      description = "The key store that contains the RSAPrivateKey to DKIM signing.")
  public void setKeyStore(final KeyStore keyStore) {
    this.keyStore = keyStore;
  }

  @PasswordAttribute(
      attributeId = DKIMJavaMailMessageEnancerComponentConstants.ATTR_KEY_STORE_PASSWORD,
      optional = true,
      label = "Key Store Password",
      description = "The password to KeyStore.")
  public void setKeyStorePassword(final String keyStorePassword) {
    this.keyStorePassword = keyStorePassword;
  }

  @BooleanAttribute(
      attributeId = DKIMJavaMailMessageEnancerComponentConstants.ATTR_USE_LENGTH_PARAM,
      defaultValue = false,
      label = "Length Param",
      description = "Use length parameter to signurate or not. More information in RFC4871.")
  public void setLengthParam(final boolean lengthParam) {
    config.lengthParam = lengthParam;
  }

  @StringAttribute(
      attributeId = DKIMJavaMailMessageEnancerComponentConstants.ATTR_PRIVATE_KEY_ALIAS,
      label = "Private Key Alias",
      description = "The alias name of the private key in the KeyStore.")
  public void setPrivateKeyAlias(final String privateKeyAlias) {
    this.privateKeyAlias = privateKeyAlias;
  }

  @StringAttribute(attributeId = DKIMJavaMailMessageEnancerComponentConstants.ATTR_SELECTOR,
      label = "Selector",
      description = "The selector subdividing the namespace for the domain tag. "
          + "More information in RFC4871.")
  public void setSelector(final String selector) {
    config.selector = selector;
  }

  /**
   * The signing algorithm or null if the default should be used.
   *
   * @param signingAlgorithm
   *          The signing algorithm or null if the default should be used.
   */
  @StringAttribute(
      attributeId = DKIMJavaMailMessageEnancerComponentConstants.ATTR_SIGNING_ALGORITHM,
      optional = true, label = "Signing Algorithm",
      description = "The algorithm that used to generate the signature. "
          + "More information in RFC4871.",
      options =

      {
          @StringAttributeOption(
              value = DKIMJavaMailMessageEnancerComponentConstants.SIGNING_ALGORITHM_SHA256_WITH_RSA, // CS_DISABLE_LINE_LENGTH
              label = DKIMJavaMailMessageEnancerComponentConstants.SIGNING_ALGORITHM_SHA256_WITH_RSA), // CS_DISABLE_LINE_LENGTH
          @StringAttributeOption(
              value = DKIMJavaMailMessageEnancerComponentConstants.SIGNING_ALGORITHM_SHA1_WITH_RSA,
              label = DKIMJavaMailMessageEnancerComponentConstants.SIGNING_ALGORITHM_SHA1_WITH_RSA)
      })

  public void setSigningAlgorithm(final String signingAlgorithm) {
    if (signingAlgorithm != null) {
      config.signingAlgorithm = SigningAlgorithm.valueOf(signingAlgorithm);
    } else {
      config.signingAlgorithm = null;
    }
  }

  @StringAttribute(attributeId = DKIMJavaMailMessageEnancerComponentConstants.ATTR_SIGNING_DOMAIN,
      label = "Signing domain",
      description = "The domain of the signing entity. More information in RFC4871.")
  public void setSigningDomain(final String signingDomain) {
    config.signingDomain = signingDomain;
  }

  @BooleanAttribute(attributeId = DKIMJavaMailMessageEnancerComponentConstants.ATTR_Z_PARAM,
      defaultValue = false,
      label = "Z Param",
      description = "Use z parameter to signurate or not. More information in RFC4871.")
  public void setzParam(final boolean zParam) {
    config.zParam = zParam;
  }
}
