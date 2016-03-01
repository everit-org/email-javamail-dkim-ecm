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
package org.everit.email.javamail.dkim.ecm.tests;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Dictionary;
import java.util.Hashtable;

import org.everit.email.javamail.dkim.ecm.DKIMJavaMailMessageEnancerComponentConstants;
import org.everit.osgi.ecm.annotation.Activate;
import org.everit.osgi.ecm.annotation.Component;
import org.everit.osgi.ecm.annotation.ConfigurationPolicy;
import org.everit.osgi.ecm.annotation.Deactivate;
import org.everit.osgi.ecm.annotation.ManualService;
import org.everit.osgi.ecm.component.ComponentContext;
import org.everit.osgi.ecm.extender.ECMExtenderConstants;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.framework.wiring.BundleWiring;

import aQute.bnd.annotation.headers.ProvideCapability;

/**
 * Sample KeyStore component.
 */
@Component(componentId = DKIMJavaMailMessageEnancerComponentConstants.SERVICE_PID,
    configurationPolicy = ConfigurationPolicy.IGNORE)
@ProvideCapability(ns = ECMExtenderConstants.CAPABILITY_NS_COMPONENT,
    value = ECMExtenderConstants.CAPABILITY_ATTR_CLASS + "" + "=${@class}")
@ManualService({ KeyStore.class })
public class KeyStoreComponent {

  private ServiceRegistration<KeyStore> registerService;

  /**
   * Component activator mehtod.
   */
  @Activate
  public void activate(final BundleContext bundleContext,
      final ComponentContext<KeyStoreComponent> componentContext) {
    Bundle bundle = bundleContext.getBundle();
    BundleWiring bundleWiring = bundle.adapt(BundleWiring.class);
    ClassLoader classLoader = bundleWiring.getClassLoader();
    try (InputStream dkimJks = classLoader.getResourceAsStream("dkim")) {
      KeyStore keystore = KeyStore.getInstance("jks");
      keystore.load(dkimJks, "changeit".toCharArray());
      Dictionary<String, ?> properties = new Hashtable<>(componentContext.getProperties());
      registerService = componentContext.registerService(KeyStore.class, keystore, properties);
    } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Component deactivator mehtod.
   */
  @Deactivate
  public void deactivate() {
    if (registerService != null) {
      registerService.unregister();
    }
  }
}
