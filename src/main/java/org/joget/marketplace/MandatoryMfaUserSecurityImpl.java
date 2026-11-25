package org.joget.marketplace;

import org.joget.apps.app.service.AppPluginUtil;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.app.service.MfaAuthenticator;
import org.joget.directory.dao.RoleDao;
import org.joget.directory.model.Role;
import org.joget.directory.model.User;
import org.joget.plugin.base.HiddenPlugin;
import org.joget.plugin.directory.UserSecurityImpl;
import org.joget.workflow.model.service.WorkflowUserManager;
import org.joget.workflow.util.WorkflowUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

import org.joget.commons.util.LogUtil;
import org.joget.commons.util.StringUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class MandatoryMfaUserSecurityImpl extends UserSecurityImpl implements HiddenPlugin {

    /**
     * Name of the plugin property that turns on MFA verification after a
     * successful Forgot Password / Change Password reset.
     */
    public static final String PROP_MFA_AFTER_PASSWORD_RESET = "mfaAfterPasswordReset";

    /**
     * Forgot Password resets end with Joget logging the user straight in, which skips the
     * MFA check that a normal login does. When enabled, drop that login and send the user
     * through the MFA step (verify the OTP, or activate MFA first) before granting access.
     */
    @Override
    protected String wsChangePasswordSubmitHandle(Map model, HttpServletRequest request, HttpServletResponse response) {
        String content = super.wsChangePasswordSubmitHandle(model, request, response);

        if (!"true".equals(getPropertyString(PROP_MFA_AFTER_PASSWORD_RESET))
                || !"true".equals(String.valueOf(model.get("updated")))) {
            return content;
        }

        MfaAuthenticator mfaAuthenticator = getMfaAuthenticator();
        if (mfaAuthenticator == null
                || !MandatoryTotpMfaAuthenticator.class.getName().equals(mfaAuthenticator.getClassName())) {
            return content;
        }

        WorkflowUserManager wum = (WorkflowUserManager) AppUtil.getApplicationContext().getBean("workflowUserManager");
        String username = getCurrentUsername(wum);
        if (isAnonymous(username)) {
            return content;
        }

        // discard the login that was just created by the password reset
        wum.setCurrentThreadUser(WorkflowUserManager.ROLE_ANONYMOUS);
        SecurityContextHolder.clearContext();
        request.getSession(true).removeAttribute("SPRING_SECURITY_CONTEXT");

        try {
            String url = mfaAuthenticator.isOtpRequired(username)
                    ? mfaAuthenticator.validateOtpUrl(username)
                    : mfaAuthenticator.activateOtpUrl(username);

            // the response is rendered inside the Change Password popup, so navigate the popup itself
            return "<script>window.location = '" + StringUtil.escapeString(url, StringUtil.TYPE_JAVASCIPT, null) + "';</script>";
        } catch (Exception e) {
            // fail closed: the login is already discarded, so the user has to sign in normally
            LogUtil.error(getClassName(), e, "Unable to start MFA after password reset");
            return "<script>parent.window.location = '" + StringUtil.escapeString(getRedirectUrl(), StringUtil.TYPE_JAVASCIPT, null) + "';</script>";
        }
    }

    /**
     * The username of the user currently logged in. Joget 8.x can keep reporting the anonymous
     * user from the workflow user manager even after the login has been placed in the Spring
     * security context (right after a password reset or OTP verification), so fall back to the
     * security context in that case.
     */
    private String getCurrentUsername(WorkflowUserManager wum) {
        String username = wum.getCurrentUsername();
        if (isAnonymous(username)) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && !isAnonymous(auth.getName())) {
                return auth.getName();
            }
        }
        return username;
    }

    private boolean isAnonymous(String username) {
        return username == null
                || username.isEmpty()
                || WorkflowUserManager.ROLE_ANONYMOUS.equals(username)
                || "anonymousUser".equals(username);
    }

    @Override
    public String getName() {
        return getMessage("mmsedm.userSecurity.name");
    }

    @Override
    public String getDescription() {
        return getMessage("mmsedm.userSecurity.description");
    }

    @Override
    public String getVersion() {
        return getMessage("mmsedm.version");
    }
    
    @Override
    public String getLabel() {
        return getMessage("mmsedm.userSecurity.label");
    }

    @Override
    public void loginPostProcessing(User user, String password, Boolean loggedIn) {
        WorkflowUserManager wum = (WorkflowUserManager) AppUtil.getApplicationContext().getBean("workflowUserManager");
        String currentUser = getCurrentUsername(wum);
        boolean isProfileUpdate = currentUser != null && currentUser.equals(user.getUsername());

        if (loggedIn && !isProfileUpdate) {
            MfaAuthenticator mfaAuthenticator = super.getMfaAuthenticator();

            boolean mandatoryMfa = true;

            //add extra logic here to determine whether this user requires mandatory MFA
            //example: admin role does not require mandatory MFA
            /*
            RoleDao roleDao = (RoleDao) AppUtil.getApplicationContext().getBean("roleDao");
            Role adminRole = roleDao.getRole("ROLE_ADMIN");
            mandatoryMfa = !user.getRoles().contains(adminRole);
            */

            //check if MFA plugin is configured, and it is matching the JwtSsoTotpMfaAuthenticator class
            HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
            if (mandatoryMfa
                    && mfaAuthenticator != null
                    && mfaAuthenticator.getClassName().equals(MandatoryTotpMfaAuthenticator.class.getName())
                    && !getMfaAuthenticator().isOtpRequired(user.getUsername())
                    && !(request != null && "cps".equals(request.getParameter("a")))
                    && !(request != null && request.getRequestURL().toString().contains(getMfaAuthenticator().getClassName()))){
                //force MFA activation
                String script = "<script>new PopupDialog('" + getMfaAuthenticator().activateOtpUrl(user.getUsername()) +"', ' ').init();</script>";
                AppUtil.setSystemAlert(script);
                throw new RuntimeException(getMfaAuthenticator().validateOtpMessage(user.getUsername()));

            } else {
                //continue with default post processing
                super.loginPostProcessing(user, password, loggedIn);
            }
        }

    }

    protected String getMessage(String key) {
        return AppPluginUtil.getMessage(key, getClassName(), Activator.MESSAGE_PATH);
    }
}
