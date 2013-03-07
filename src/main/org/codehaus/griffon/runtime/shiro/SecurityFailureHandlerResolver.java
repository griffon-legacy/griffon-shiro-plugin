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

package org.codehaus.griffon.runtime.shiro;

import griffon.core.GriffonApplication;
import griffon.core.GriffonController;
import griffon.plugins.shiro.SecurityFailureHandler;
import org.apache.shiro.subject.Subject;

import static org.codehaus.griffon.runtime.util.GriffonApplicationHelper.safeLoadClass;

/**
 * @author Andres Almiray
 */
public class SecurityFailureHandlerResolver implements SecurityFailureHandler {
    private final GriffonApplication app;
    private final ShiroGriffonControllerActionInterceptor interceptor;
    private final String handlerClassName;

    public SecurityFailureHandlerResolver(GriffonApplication app, ShiroGriffonControllerActionInterceptor interceptor, String handlerClassName) {
        this.app = app;
        this.interceptor = interceptor;
        this.handlerClassName = handlerClassName;
    }

    public void handleFailure(Subject subject, Kind kind, GriffonController controller, String actionName) {
        Class handlerClass = safeLoadClass(handlerClassName);
        SecurityFailureHandler securityFailureHandler = (SecurityFailureHandler) app.newInstance(handlerClass, "");
        interceptor.securityFailureHandler = securityFailureHandler;
        securityFailureHandler.handleFailure(subject, kind, controller, actionName);
    }
}
