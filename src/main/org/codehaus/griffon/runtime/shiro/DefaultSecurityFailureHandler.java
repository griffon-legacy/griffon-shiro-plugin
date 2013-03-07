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

import griffon.core.GriffonController;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andres Almiray
 */
public class DefaultSecurityFailureHandler extends AbstractSecurityFailureHandler {
    private final Logger LOG = LoggerFactory.getLogger(DefaultSecurityFailureHandler.class);

    public void handleFailure(Subject subject, Kind kind, GriffonController controller, String actionName) {
        if (LOG.isInfoEnabled()) {
            switch (kind) {
                case AUTHENTICATION:
                    LOG.info("Subject failed authentication challenge on " + qualifyActionName(controller, actionName));
                    break;
                case PERMISSIONS:
                    LOG.info("Subject was not granted access to " + qualifyActionName(controller, actionName) + " due to lack of permissions");
                    break;
                case ROLES:
                    LOG.info("Subject was not granted access to " + qualifyActionName(controller, actionName) + " due to lack of roles");
                    break;
                case GUEST:
                default:
                    LOG.info("Subject failed guest challenge on " + qualifyActionName(controller, actionName));
            }
        }
    }
}
