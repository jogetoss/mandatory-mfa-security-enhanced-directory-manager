package org.joget.marketplace;

import org.joget.apps.app.service.AppPluginUtil;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.app.service.MfaAuthenticator;
import org.joget.commons.util.StringUtil;
import org.joget.directory.dao.RoleDao;
import org.joget.directory.model.Role;
import org.joget.directory.model.User;
import org.joget.plugin.base.HiddenPlugin;
import org.joget.plugin.directory.UserSecurityImpl;
import org.joget.workflow.model.service.WorkflowUserManager;
import org.joget.workflow.util.WorkflowUtil;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.security.core.context.SecurityContextHolder;

public class MandatoryMfaUserSecurityImpl extends UserSecurityImpl implements HiddenPlugin {

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
        String currentUser = wum.getCurrentUsername();
        boolean isProfileUpdate = currentUser.equals(user.getUsername());

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

    /**
     * Core SEDM skips the MFA check for the change password submission (a=cps) and then
     * logs the user in directly. Since the Forgot Password link and the expired password
     * popup both submit to a=cps, the user ends up with a session without completing MFA.
     *
     * Let core save the new password, then end the session it just created and send the
     * user back to the login page they came from, so that MFA (or forced MFA activation)
     * is enforced on the next login.
     */
    @Override
    protected String wsChangePasswordSubmitHandle(Map model, HttpServletRequest request, HttpServletResponse response) {
        String content = super.wsChangePasswordSubmitHandle(model, request, response);

        if ("true".equals(model.get("updated")) && getMfaAuthenticator() != null) {
            //logout, same approach as MandatoryTotpMfaAuthenticator
            WorkflowUserManager wum = (WorkflowUserManager) AppUtil.getApplicationContext().getBean("workflowUserManager");
            wum.setCurrentThreadUser(WorkflowUserManager.ROLE_ANONYMOUS);
            SecurityContextHolder.clearContext();

            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute("SPRING_SECURITY_CONTEXT");
            }

            //discard the system alert set by core for this login (eg. last login info), it is not a valid login anymore
            AppUtil.getSystemAlert();

            //we are inside the popup iframe, reload the parent login page (/web/login or /web/ulogin/...) without the token,
            //fallback to the default login page if the parent is not a login page
            String message = StringUtil.escapeString(getMessage("mmsedm.passwordChanged.relogin"), StringUtil.TYPE_JAVASCIPT, null);
            String loginUrl = StringUtil.escapeString(request.getContextPath() + "/web/login", StringUtil.TYPE_JAVASCIPT, null);
            content = "<script>"
                    + "alert('" + message + "');"
                    + "var path = parent.window.location.pathname;"
                    + "if (path.indexOf('/web/login') === -1 && path.indexOf('/ulogin/') === -1) { path = '" + loginUrl + "'; }"
                    + "parent.window.location.replace(path);"
                    + "</script>";
        }
        return content;
    }

    /**
     * The login page opens the change password popup whenever it finds a forgot password token,
     * either in its own URL (the link in the email, /web/login?t=...) or in the saved request / referer.
     * Once the password is reset the token is deleted, so loading that URL again (redirect back,
     * refresh, back button or clicking the email link again) would show a popup with
     * "Invalid forgot password token". Ignore a token that no longer exists so the normal login
     * page is shown instead. A valid token still opens the change password popup.
     */
    @Override
    protected String getForgotPasswordToken() {
        String token = super.getForgotPasswordToken();
        if (token != null && getUserPasswordHistoryDao() != null
                && getUserPasswordHistoryDao().getUserPasswordHistoryById(token) == null) {
            token = null;
        }
        return token;
    }

    protected String getMessage(String key) {
        return AppPluginUtil.getMessage(key, getClassName(), Activator.MESSAGE_PATH);
    }
}
