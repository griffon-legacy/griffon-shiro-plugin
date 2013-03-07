/*
 * Copyright 2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import griffon.core.GriffonApplication;
import griffon.plugins.shiro.SubjectHolder;
import griffon.plugins.shiro.factory.SecurityManagerFactory;
import griffon.util.ApplicationHolder;
import griffon.util.CollectionUtils;
import griffon.util.RunnableWithArgs;
import griffon.util.RunnableWithArgsClosure;
import org.apache.shiro.SecurityUtils;
import org.codehaus.griffon.runtime.core.AbstractGriffonAddon;
import org.codehaus.griffon.runtime.shiro.ShiroGriffonControllerActionInterceptor;

import static griffon.util.ConfigUtils.getConfigValueAsString;
import static org.codehaus.griffon.runtime.util.GriffonApplicationHelper.safeLoadClass;

/**
 * @author Andres Almiray
 */
public class ShiroGriffonAddon extends AbstractGriffonAddon {
    private static final String DEFAULT_SECURITY_MANAGER_FACTORY = "org.codehaus.griffon.runtime.shiro.DefaultSecurityManagerFactory";
    private static final String KEY_SECURITY_MANAGER_FACTORY = "shiro.security.manager.factory";

    public ShiroGriffonAddon() {
        super(ApplicationHolder.getApplication());

        actionInterceptors.put(
            "security",
            CollectionUtils.<String, Object>map()
                .e("interceptor", ShiroGriffonControllerActionInterceptor.class.getName())
        );

        events.put(GriffonApplication.Event.LOAD_ADDONS_END.getName(), new RunnableWithArgsClosure(new RunnableWithArgs() {
            @Override
            public void run(Object[] args) {
                initialize();
            }
        }));
    }

    private void initialize() {
        String className = getConfigValueAsString(getApp().getConfig(), KEY_SECURITY_MANAGER_FACTORY, DEFAULT_SECURITY_MANAGER_FACTORY);
        if (getLog().isDebugEnabled()) {
            getLog().debug("Using " + className + " as SecurityManagerFactory");
        }
        Class factoryClass = safeLoadClass(className);
        SecurityManagerFactory factory = (SecurityManagerFactory) getApp().newInstance(factoryClass, "");
        SecurityUtils.setSecurityManager(factory.createSecurityManager(getApp()));
        SubjectHolder.setSubject(SecurityUtils.getSubject());
    }
}