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
import java.util.Dictionary;
import java.util.Hashtable;

import org.everit.email.javamail.dkim.MessageDKIMSigner;
import org.everit.email.javamail.dkim.MessageDKIMSignerConfig;
import org.everit.email.javamail.dkim.ecm.MessageDKIMSignerComponentConstants;
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
@Component(componentId = MessageDKIMSignerComponentConstants.SERVICE_PID,
    configurationPolicy = ConfigurationPolicy.FACTORY,
    label = "Everit Message DKIMSigner Component",
    description = "Java Mail Message enhancer implemantation that message sign with DKIM.")
@ProvideCapability(ns = ECMExtenderConstants.CAPABILITY_NS_COMPONENT,
    value = ECMExtenderConstants.CAPABILITY_ATTR_CLASS + "" + "=${@class}")
@ManualService({ JavaMailMessageEnhancer.class })
public class MessageDKIMSignerComponent {

  private Canonicalization bodyCanonicalization;

  private Canonicalization headerCanonicalization;

  private String identity;

  private KeyStore keyStore;

  private String keyStorePassword;

  private boolean lengthParam;

  private String privateKeyAlias;

  private String selector;

  private ServiceRegistration<JavaMailMessageEnhancer> serviceRegistration;

  private SigningAlgorithm signingAlgorithm;

  private String signingDomain;

  private boolean zParam;

  /**
   * Creates the {@link MessageDKIMSigner} and registers it as an OSGi service.
   *
   * @param componentContext
   *          The context of the component.
   */
  @Activate
  public void activate(final ComponentContext<MessageDKIMSignerComponent> componentContext) {
    MessageDKIMSignerConfig config = new MessageDKIMSignerConfig();
    config.privateKey(readPrivateKey());
    config.signingDomain(signingDomain);
    config.selector(selector);
    config.identity(identity);
    config.headerCanonicalization(headerCanonicalization);
    config.bodyCanonicalization(bodyCanonicalization);
    config.signingAlgorithm(signingAlgorithm);
    config.lengthParam(lengthParam);
    config.zParam(zParam);

    JavaMailMessageEnhancer messageDKIMSigner = new MessageDKIMSigner(config);
    Dictionary<String, ?> properties = new Hashtable<>(componentContext.getProperties());

    serviceRegistration = componentContext.registerService(JavaMailMessageEnhancer.class,
        messageDKIMSigner,
        properties);
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

  @StringAttribute(
      attributeId = MessageDKIMSignerComponentConstants.ATTR_BODY_CANONICALIZATION,
      label = "Body canonicalization",
      description = "The canonicalization to be used for the body. More information in RFC4871.",
      options = {
          @StringAttributeOption(
              value = MessageDKIMSignerComponentConstants.CANONICALIZATION_SIMPLE,
              label = MessageDKIMSignerComponentConstants.CANONICALIZATION_SIMPLE),
          @StringAttributeOption(
              value = MessageDKIMSignerComponentConstants.CANONICALIZATION_RELAXED,
              label = MessageDKIMSignerComponentConstants.CANONICALIZATION_RELAXED)
      })
  public void setBodyCanonicalization(final String bodyCanonicalization) {
    this.bodyCanonicalization = Canonicalization.valueOf(bodyCanonicalization);
  }

  @StringAttribute(
      attributeId = MessageDKIMSignerComponentConstants.ATTR_HEADER_CANONICALIZATION,
      label = "Header canonicalization",
      description = "The canonicalization to be used for the header. More information in RFC4871.",
      options = {
          @StringAttributeOption(
              value = MessageDKIMSignerComponentConstants.CANONICALIZATION_SIMPLE,
              label = MessageDKIMSignerComponentConstants.CANONICALIZATION_SIMPLE),
          @StringAttributeOption(
              value = MessageDKIMSignerComponentConstants.CANONICALIZATION_RELAXED,
              label = MessageDKIMSignerComponentConstants.CANONICALIZATION_RELAXED)
      })
  public void setHeaderCanonicalization(final String headerCanonicalization) {
    this.headerCanonicalization = Canonicalization.valueOf(headerCanonicalization);
  }

  @StringAttribute(attributeId = MessageDKIMSignerComponentConstants.ATTR_IDENTITY,
      optional = true,
      label = "Identity",
      description = "Identity of the user or agent (e.g., a mailing list manager) "
          + "on behalf of which this message is signed. More information in RFC4871.")
  public void setIdentity(final String identity) {
    this.identity = identity;
  }

  @ServiceRef(attributeId = MessageDKIMSignerComponentConstants.ATTR_KEY_STORE,
      referenceId = MessageDKIMSignerComponentConstants.References.SERVICE_REF_KEY_STORE,
      label = "Key store",
      description = "The key store that contains the RSAPrivateKey to DKIM signing.")
  public void setKeyStore(final KeyStore keyStore) {
    this.keyStore = keyStore;
  }

  @PasswordAttribute(attributeId = MessageDKIMSignerComponentConstants.ATTR_KEY_STORE_PASSWORD,
      label = "Key Store Password",
      description = "The password to KeyStore.")
  public void setKeyStorePassword(final String keyStorePassword) {
    this.keyStorePassword = keyStorePassword;
  }

  @BooleanAttribute(attributeId = MessageDKIMSignerComponentConstants.ATTR_USE_LENGTH_PARAM,
      label = "Length Param",
      description = "Use length parameter to signurate or not. More information in RFC4871.")
  public void setLengthParam(final boolean lengthParam) {
    this.lengthParam = lengthParam;
  }

  @StringAttribute(attributeId = MessageDKIMSignerComponentConstants.ATTR_PRIVATE_KEY_ALIAS,
      label = "Private Key Alias",
      description = "The alias name of the private key in the KeyStore.")
  public void setPrivateKeyAlias(final String privateKeyAlias) {
    this.privateKeyAlias = privateKeyAlias;
  }

  @StringAttribute(attributeId = MessageDKIMSignerComponentConstants.ATTR_SELECTOR,
      label = "Selector",
      description = "The selector subdividing the namespace for the domain tag. "
          + "More information in RFC4871.")
  public void setSelector(final String selector) {
    this.selector = selector;
  }

  @StringAttribute(attributeId = MessageDKIMSignerComponentConstants.ATTR_SIGNING_ALGORITHM,
      label = "Signing Algorithm",
      description = "The algorithm that used to generate the signature. "
          + "More information in RFC4871.",
      options = {
          @StringAttributeOption(
              value = MessageDKIMSignerComponentConstants.SIGNING_ALGORITHM_SHA256_WITH_RSA,
              label = MessageDKIMSignerComponentConstants.SIGNING_ALGORITHM_SHA256_WITH_RSA),
          @StringAttributeOption(
              value = MessageDKIMSignerComponentConstants.SIGNING_ALGORITHM_SHA1_WITH_RSA,
              label = MessageDKIMSignerComponentConstants.SIGNING_ALGORITHM_SHA1_WITH_RSA)
      })
  public void setSigningAlgorithm(final String signingAlgorithm) {
    this.signingAlgorithm = SigningAlgorithm.valueOf(signingAlgorithm);
  }

  @StringAttribute(attributeId = MessageDKIMSignerComponentConstants.ATTR_SIGNING_DOMAIN,
      label = "Signing domain",
      description = "The domain of the signing entity. More information in RFC4871.")
  public void setSigningDomain(final String signingDomain) {
    this.signingDomain = signingDomain;
  }

  @BooleanAttribute(attributeId = MessageDKIMSignerComponentConstants.ATTR_Z_PARAM,
      label = "Z Param",
      description = "Use z parameter to signurate or not. More information in RFC4871.")
  public void setzParam(final boolean zParam) {
    this.zParam = zParam;
  }
}
