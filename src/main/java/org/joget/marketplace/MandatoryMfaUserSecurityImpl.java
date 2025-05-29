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

    protected String getMessage(String key) {
        return AppPluginUtil.getMessage(key, getClassName(), Activator.MESSAGE_PATH);
    }
}
