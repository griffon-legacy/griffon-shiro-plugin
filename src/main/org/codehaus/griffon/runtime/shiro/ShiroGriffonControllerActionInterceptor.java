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
import griffon.plugins.shiro.SubjectHolder;
import griffon.plugins.shiro.annotation.*;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.subject.Subject;
import org.codehaus.griffon.runtime.core.controller.AbstractGriffonControllerActionInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static griffon.util.ConfigUtils.getConfigValueAsString;

/**
 * @author Andres Almiray
 */
public class ShiroGriffonControllerActionInterceptor extends AbstractGriffonControllerActionInterceptor {
    private final Logger LOG = LoggerFactory.getLogger(ShiroGriffonControllerActionInterceptor.class);
    private final Map<String, ActionRequirement> requirementsPerAction = new LinkedHashMap<String, ActionRequirement>();

    public void configure(GriffonController controller, String actionName, Method method) {
        configureAction(controller, actionName, method);
    }

    public void configure(GriffonController controller, String actionName, Field closure) {
        configureAction(controller, actionName, closure);
    }

    public Object[] before(GriffonController controller, String actionName, Object[] args) {
        String fqActionName = qualifyActionName(controller, actionName);
        ActionRequirement actionRequirement = requirementsPerAction.get(fqActionName);

        if (actionRequirement != null) {
            Subject subject = SubjectHolder.getSubject();
            for (RequirementConfiguration requirementConfiguration : actionRequirement.getRequirements()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Evaluating security requirement " + requirementConfiguration);
                }
                if (!requirementConfiguration.eval(subject)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Subject did not meet expected security requirements.");
                    }
                    switch (requirementConfiguration.requirement) {
                        case AUTHENTICATION:
                            securityFailureHandler.handleFailure(subject,
                                SecurityFailureHandler.Kind.AUTHENTICATION,
                                controller, actionName);
                            break;
                        case ROLES:
                            securityFailureHandler.handleFailure(subject,
                                SecurityFailureHandler.Kind.ROLES,
                                controller, actionName);
                            break;
                        case PERMISSIONS:
                            securityFailureHandler.handleFailure(subject,
                                SecurityFailureHandler.Kind.PERMISSIONS,
                                controller, actionName);
                            break;
                        case GUEST:
                        default:
                            securityFailureHandler.handleFailure(subject,
                                SecurityFailureHandler.Kind.GUEST,
                                controller, actionName);

                    }
                    throw abortActionExecution();
                }
            }
        }

        return args;
    }

    // ===================================================

    SecurityFailureHandler securityFailureHandler;

    private static final String DEFAULT_SECURITY_FAILURE_HANDLER = "org.codehaus.griffon.runtime.shiro.DefaultSecurityFailureHandler";
    private static final String KEY_SECURITY_FAILURE_HANDLER = "shiro.security.failure.handler";

    @Override
    public void setApp(GriffonApplication app) {
        super.setApp(app);

        String handlerClassName = getConfigValueAsString(app.getConfig(), KEY_SECURITY_FAILURE_HANDLER, DEFAULT_SECURITY_FAILURE_HANDLER);
        securityFailureHandler = new SecurityFailureHandlerResolver(app, this, handlerClassName);
    }

    // ===================================================

    private void configureAction(GriffonController controller, String actionName, AnnotatedElement annotatedElement) {
        String fqActionName = qualifyActionName(controller, actionName);
        if (requirementsPerAction.get(fqActionName) != null) return;

        Map<Requirement, RequirementConfiguration> requirements = new LinkedHashMap<Requirement, RequirementConfiguration>();

        // grab global requirements from controller
        processRequiresGuest(controller.getClass().getAnnotation(RequiresGuest.class), requirements);
        processRequiresAuthentication(controller.getClass().getAnnotation(RequiresAuthentication.class), requirements);
        processRequiresRoles(controller.getClass().getAnnotation(RequiresRoles.class), requirements);
        processRequiresPermissions(controller.getClass().getAnnotation(RequiresPermissions.class), requirements);

        // grab local requirements from action
        processRequiresGuest(annotatedElement.getAnnotation(RequiresGuest.class), requirements);
        processRequiresAuthentication(annotatedElement.getAnnotation(RequiresAuthentication.class), requirements);
        processRequiresRoles(annotatedElement.getAnnotation(RequiresRoles.class), requirements);
        processRequiresPermissions(annotatedElement.getAnnotation(RequiresPermissions.class), requirements);

        requirementsPerAction.put(fqActionName, new ActionRequirement(
            fqActionName,
            requirements.values().toArray(new RequirementConfiguration[requirements.size()])
        ));
    }

    private String qualifyActionName(GriffonController controller, String actionName) {
        return controller.getClass().getName() + "." + actionName;
    }

    private void processRequiresAuthentication(RequiresAuthentication annotation, Map<Requirement, RequirementConfiguration> requirements) {
        if (annotation == null) return;
        requirements.remove(Requirement.GUEST);
        requirements.put(Requirement.AUTHENTICATION, new RequirementConfiguration(Requirement.AUTHENTICATION));
    }

    private void processRequiresRoles(RequiresRoles annotation, Map<Requirement, RequirementConfiguration> requirements) {
        if (annotation == null) return;
        String[] value = annotation.value();
        Logical logical = annotation.logical();
        requirements.remove(Requirement.GUEST);
        requirements.put(Requirement.ROLES, new RequirementConfiguration(Requirement.ROLES, value, logical));
    }

    private void processRequiresPermissions(RequiresPermissions annotation, Map<Requirement, RequirementConfiguration> requirements) {
        if (annotation == null) return;
        String[] value = annotation.value();
        Logical logical = annotation.logical();
        requirements.remove(Requirement.GUEST);
        requirements.put(Requirement.PERMISSIONS, new RequirementConfiguration(Requirement.PERMISSIONS, value, logical));
    }

    private void processRequiresGuest(RequiresGuest annotation, Map<Requirement, RequirementConfiguration> requirements) {
        if (annotation == null) return;
        requirements.clear();
        requirements.put(Requirement.GUEST, new RequirementConfiguration(Requirement.GUEST));
    }

    private enum Requirement {
        AUTHENTICATION(new AuthenticationRequirementEvaluator()),
        ROLES(new RolesRequirementEvaluator()),
        PERMISSIONS(new PermissionsRequirementEvaluator()),
        GUEST(new GuestRequirementEvaluator());

        private final RequirementEvaluator requirementEvaluator;

        private Requirement(RequirementEvaluator requirementEvaluator) {
            this.requirementEvaluator = requirementEvaluator;
        }

        private boolean eval(RequirementConfiguration requirementConfig, Subject subject) {
            return requirementEvaluator.eval(requirementConfig, subject);
        }
    }

    private static interface RequirementEvaluator {
        boolean eval(RequirementConfiguration requirementConfig, Subject subject);
    }

    private static class AuthenticationRequirementEvaluator implements RequirementEvaluator {
        public boolean eval(RequirementConfiguration requirementConfig, Subject subject) {
            return subject.isAuthenticated();
        }
    }

    private static class GuestRequirementEvaluator implements RequirementEvaluator {
        public boolean eval(RequirementConfiguration requirementConfig, Subject subject) {
            return subject.getPrincipal() == null;
        }
    }

    private static class RolesRequirementEvaluator implements RequirementEvaluator {
        public boolean eval(RequirementConfiguration requirementConfig, Subject subject) {
            String[] roles = requirementConfig.getValues();
            Logical logical = requirementConfig.getLogical();

            try {
                if (roles.length == 1) {
                    subject.checkRole(roles[0]);
                } else if (Logical.AND.equals(logical)) {
                    subject.checkRoles(Arrays.asList(roles));
                } else if (Logical.OR.equals(logical)) {
                    boolean hasAtLeastOneRole = false;
                    for (String role : roles) {
                        if (subject.hasRole(role)) {
                            hasAtLeastOneRole = true;
                        }
                    }
                    if (!hasAtLeastOneRole) {
                        subject.checkRole(roles[0]);
                    } else {
                        return true;
                    }
                }
            } catch (AuthorizationException ae) {
                return false;
            }

            return true;
        }
    }

    private static class PermissionsRequirementEvaluator implements RequirementEvaluator {
        public boolean eval(RequirementConfiguration requirementConfig, Subject subject) {
            String[] perms = requirementConfig.getValues();
            Logical logical = requirementConfig.getLogical();

            try {
                if (perms.length == 1) {
                    subject.checkPermission(perms[0]);
                } else if (Logical.AND.equals(logical)) {
                    subject.checkPermissions(perms);
                } else if (Logical.OR.equals(logical)) {
                    boolean hasAtLeastOnePermission = false;
                    for (String permission : perms) {
                        if (subject.isPermitted(permission)) {
                            hasAtLeastOnePermission = true;
                        }
                    }
                    if (!hasAtLeastOnePermission) {
                        subject.checkPermission(perms[0]);
                    } else {
                        return true;
                    }
                }
            } catch (AuthorizationException ae) {
                return false;
            }

            return true;
        }
    }

    private static class ActionRequirement {
        private final String actionName;
        private final RequirementConfiguration[] requirements;

        private ActionRequirement(String actionName, RequirementConfiguration[] requirements) {
            this.actionName = actionName;
            this.requirements = requirements;
        }

        public String getActionName() {
            return actionName;
        }

        public RequirementConfiguration[] getRequirements() {
            return requirements;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            ActionRequirement that = (ActionRequirement) o;

            if (!actionName.equals(that.actionName)) return false;
            if (!Arrays.equals(requirements, that.requirements)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = actionName.hashCode();
            result = 31 * result + Arrays.hashCode(requirements);
            return result;
        }

        @Override
        public String toString() {
            return "ActionRequirement{" +
                "actionName='" + actionName + '\'' +
                ", requirements=" + (requirements == null ? null : Arrays.asList(requirements)) +
                '}';
        }
    }

    private static class RequirementConfiguration {
        private static final String[] EMPTY = new String[0];
        private final Requirement requirement;
        private final String[] values;
        private final Logical logical;

        private RequirementConfiguration(Requirement requirement) {
            this(requirement, EMPTY, Logical.AND);
        }

        private RequirementConfiguration(Requirement requirement, String[] values, Logical logical) {
            this.requirement = requirement;
            this.values = values;
            this.logical = logical;
        }

        public Requirement getRequirement() {
            return requirement;
        }

        public String[] getValues() {
            return values;
        }

        public Logical getLogical() {
            return logical;
        }

        public boolean eval(Subject subject) {
            return requirement.eval(this, subject);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            RequirementConfiguration that = (RequirementConfiguration) o;

            if (logical != that.logical) return false;
            if (requirement != that.requirement) return false;
            if (!Arrays.equals(values, that.values)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = requirement.hashCode();
            result = 31 * result + Arrays.hashCode(values);
            result = 31 * result + logical.hashCode();
            return result;
        }

        @Override
        public String toString() {
            return "RequirementConfiguration{" +
                "requirement=" + requirement +
                ", values=" + (values == null ? null : Arrays.asList(values)) +
                ", logical=" + logical +
                '}';
        }
    }
}
