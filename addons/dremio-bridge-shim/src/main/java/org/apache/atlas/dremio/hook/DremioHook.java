/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.atlas.dremio.hook;

import java.security.PrivilegedActionException;

import org.apache.atlas.plugin.classloader.AtlasPluginClassLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.dremio.service.SingletonRegistry;
import com.dremio.service.namespace.NameSpaceChangeListener;
import com.dremio.service.namespace.NamespaceKey;
import com.dremio.service.namespace.NamespaceService;
import com.dremio.service.namespace.proto.NameSpaceContainer;

/**
 * Dremio hook used for atlas entity registration.
 */
public class DremioHook implements NameSpaceChangeListener {
  private static final Logger LOG = LoggerFactory.getLogger(DremioHook.class);

  private static final String DREMIO_PLUGIN_TYPE = "dremio";

  private static final String DREMIO_HIVE_HOOK_IMPL_CLASSNAME = "org.apache.atlas.dremio.hook.DremioHook";

  private AtlasPluginClassLoader atlasPluginClassLoader = null;

  private NameSpaceChangeListener dremioHook;

  public DremioHook() {
    this.initialize();
  }

  private void initialize() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> DremioHook.initialize()");
    }

    try {
      atlasPluginClassLoader = AtlasPluginClassLoader.getInstance(DREMIO_PLUGIN_TYPE, this.getClass());
      @SuppressWarnings("unchecked")
      Class<NameSpaceChangeListener> cls = (Class<NameSpaceChangeListener>) Class.forName(DREMIO_HIVE_HOOK_IMPL_CLASSNAME, true, atlasPluginClassLoader);

      activatePluginClassLoader();
      dremioHook = cls.newInstance();

    } catch (Exception excp) {
      LOG.error("Error instantiating Atlas hook implementation", excp);
    } finally {
      deactivatePluginClassLoader();
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== DremioHook.initialize()");
    }
  }

  private void activatePluginClassLoader() {
    if (atlasPluginClassLoader != null) {
      atlasPluginClassLoader.activate();
    }
  }

  private void deactivatePluginClassLoader() {
    if (atlasPluginClassLoader != null) {
      atlasPluginClassLoader.deactivate();
    }
  }

  @Override
  public void init(SingletonRegistry registry) {
    LOG.error("DremioHook.initialize.");
    this.initialize();
    NamespaceService.addChangeListener(this);
  }

  @Override
  public void beforeUpdate(NamespaceKey key, NameSpaceContainer v) {
    try {
      atlasPluginClassLoader = AtlasPluginClassLoader.getInstance(DREMIO_PLUGIN_TYPE, this.getClass());

      activatePluginClassLoader();
      dremioHook.beforeUpdate(key, v);
    } catch (PrivilegedActionException e) {
    } finally {
      deactivatePluginClassLoader();
    }

  }

  @Override
  public void afterUpdate(NamespaceKey key, NameSpaceContainer v) {
    try {
      atlasPluginClassLoader = AtlasPluginClassLoader.getInstance(DREMIO_PLUGIN_TYPE, this.getClass());

      activatePluginClassLoader();
      dremioHook.afterUpdate(key, v);
    } catch (PrivilegedActionException e) {
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void beforeDelete(NamespaceKey key, String previousVersion) {
    try {
      atlasPluginClassLoader = AtlasPluginClassLoader.getInstance(DREMIO_PLUGIN_TYPE, this.getClass());

      activatePluginClassLoader();
      dremioHook.beforeDelete(key, previousVersion);
    } catch (PrivilegedActionException e) {
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void afterDelete(NamespaceKey key, String previousVersion) {
    try {
      atlasPluginClassLoader = AtlasPluginClassLoader.getInstance(DREMIO_PLUGIN_TYPE, this.getClass());

      activatePluginClassLoader();
      dremioHook.afterDelete(key, previousVersion);
    } catch (PrivilegedActionException e) {
    } finally {
      deactivatePluginClassLoader();
    }
  }
}
