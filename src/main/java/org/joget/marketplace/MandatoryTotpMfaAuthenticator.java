package org.joget.marketplace;

import org.joget.apps.app.service.AppPluginUtil;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.workflow.security.WorkflowUserDetails;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.commons.util.SecurityUtil;
import org.joget.directory.dao.UserMetaDataDao;
import org.joget.directory.model.Role;
import org.joget.directory.model.User;
import org.joget.directory.model.UserMetaData;
import org.joget.directory.model.service.DirectoryUtil;
import org.joget.directory.model.service.ExtDirectoryManager;
import org.joget.directory.model.service.UserSecurity;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.directory.TotpMfaAuthenticator;
import org.joget.workflow.model.dao.WorkflowHelper;
import org.joget.workflow.model.service.WorkflowUserManager;
import org.joget.workflow.util.WorkflowUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;

public class MandatoryTotpMfaAuthenticator extends TotpMfaAuthenticator {

    public static String KEY = "TOTP_SECRET";

    public String getName() {
        return getMessage("mmsedm.totp.name");
    }

    public String getVersion() {
        return getMessage("mmsedm.version");
    }

    public String getDescription() {
        return getMessage("mmsedm.totp.description");
    }

    public String getLabel() {
        return getMessage("mmsedm.totp.label");
    }

    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        UserSecurity us = DirectoryUtil.getUserSecurity();
        setProperties(us.getProperties());

        String content = "";
        Map model = new HashMap();
        model.put("request", request);

        String action = request.getParameter("a");
        if (action != null) {
            if ("etotp".equals(action)) {
                content = wsEnableTotpAuthHandle(model, request, response);
            } else if ("etotps".equals(action)) {
                content = wsEnableTotpAuthSubmitHandle(model, request, response);
            } else if ("vp".equals(action)) {
                content = wsVerifyPinHandle(model, request, response);
            } else if ("vps".equals(action)) {
                content = wsVerifyPinSubmitHandle(model, request, response);
            } else if ("fetotp".equals(action)) {
                content = wsForceEnableTotpAuthHandle(model, request, response);
            } else if ("fetotps".equals(action)) {
                try {
                    content = wsForceEnableTotpAuthSubmitHandle(model, request, response);
                }catch (Exception e) {
                    //if any loginPostProcessing after activating MFA throws exception (eg. password expiry)
                    String systemAlert = AppUtil.getSystemAlert();
                    if(systemAlert != null && systemAlert.length() > 0) {
                        //logout
                        WorkflowUserManager wum = (WorkflowUserManager) AppUtil.getApplicationContext().getBean("workflowUserManager");
                        wum.setCurrentThreadUser(WorkflowUserManager.ROLE_ANONYMOUS);
                        SecurityContextHolder.clearContext();

                        HttpSession session = request.getSession(true);
                        session.removeAttribute("SPRING_SECURITY_CONTEXT");

                        //we are already inside a popup, inject script to make sure no nested PopupDialog, replace own (iframe) URL instead
                        content = "<script>PopupDialog.prototype.show = function(){ window.location = this.src }</script>";
                        content += systemAlert;
                    }
                }
            }
        }

        if (content != null && !content.isEmpty()) {
            request.setAttribute("content", content);
            request.getRequestDispatcher("/WEB-INF/jsp/console/popupTemplate.jsp").forward(request, response);
        } else {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
        }
    }

    @Override
    public String activateOtpUrl(String username) {
        String encryptedUsername = SecurityUtil.encrypt(username);
        String url = null;

        try {
            url = AppUtil.getRequestContextPath() + "/web/json/plugin/"+getClassName()+"/service?a=fetotp&u="+ URLEncoder.encode(encryptedUsername, "UTF-8");
        } catch (Exception e) {}

        return url;
    }

    protected String wsForceEnableTotpAuthHandle(Map model, HttpServletRequest request, HttpServletResponse response) throws IOException {
        UserSecurity us = DirectoryUtil.getUserSecurity();
        String tempusername = request.getParameter("u");
        if (tempusername != null) {
            String username = SecurityUtil.decrypt(tempusername);
            String secret = this.getRandomSecretKey();
            model.put("secret", secret);
            model.put("barcodeUrl", this.getQRBarcode(username, WorkflowUtil.getHttpServletRequest().getServerName(), secret));
            try {
                String nonce = SecurityUtil.generateNonce(new String[]{tempusername, secret}, 1);
                model.put("url", AppUtil.getRequestContextPath() + "/web/json/plugin/"+getClassName()+"/service?a=fetotps&u="+URLEncoder.encode(tempusername, "UTF-8")+"&nonce="+URLEncoder.encode(nonce, "UTF-8"));
            } catch (UnsupportedEncodingException ex) {
            }
            return this.getTemplate("forceEnableTotpAuth", model);
        }

        return this.getTemplate("unauthorized", model);
    }

    protected String wsForceEnableTotpAuthSubmitHandle(Map model, HttpServletRequest request, HttpServletResponse response) throws IOException {
        UserSecurity us = DirectoryUtil.getUserSecurity();
        String tempusername = request.getParameter("u");
        UserMetaDataDao dao = (UserMetaDataDao)AppUtil.getApplicationContext().getBean("userMetaDataDao");
        UserMetaData data = dao.getUserMetaData(tempusername, KEY);
        if (tempusername != null) {
            String username = SecurityUtil.decrypt(tempusername);

            if ("POST".equalsIgnoreCase(request.getMethod()) && data == null) {
                String secret = request.getParameter("secret");
                String pin = request.getParameter("pin");
                String nonce = request.getParameter("nonce");

                if (secret == null || !SecurityUtil.verifyNonce(nonce, new String[] {tempusername, secret})) {
                    return getTemplate("unauthorized", model);
                }

                if (pin != null && secret != null && pin.equals(this.getTOTPCode(secret))) {
                    model.put("secret", secret);

                    data = new UserMetaData();
                    data.setUsername(username);
                    data.setKey(KEY);
                    data.setValue(secret);

                    dao.addUserMetaData(data);

                    return loginUser(username, request);

                } else {
                    model.put("secret", secret);
                    model.put("barcodeUrl", this.getQRBarcode(username, WorkflowUtil.getHttpServletRequest().getServerName(), secret));
                    model.put("error", getMessage("totp.invalid"));
                    try {
                        model.put("url", AppUtil.getRequestContextPath() + "/web/json/plugin/"+getClassName()+"/service?a=fetotps&u="+URLEncoder.encode(tempusername, "UTF-8")+"&nonce="+URLEncoder.encode(nonce, "UTF-8"));
                    } catch (UnsupportedEncodingException ex) {
                    }
                    return this.getTemplate("forceEnableTotpAuth", model);
                }
            }
        }

        return this.getTemplate("unauthorized", model);
    }

    @Override
    protected String getTemplate(String template, Map model) {
        // display license page
        PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");

        String content = "";
        if (template.equals("verifyPin") || template.equals("forceEnableTotpAuth")) {
            content = pluginManager.getPluginFreeMarkerTemplate(model, getClass().getName(), "/templates/" + template + ".ftl", Activator.MESSAGE_PATH);
        }else{
            content = pluginManager.getPluginFreeMarkerTemplate(model, TotpMfaAuthenticator.class.getName(), "/templates/" + template + ".ftl", null);
        }

        return content;
    }

    protected String getMessage(String key) {
        return AppPluginUtil.getMessage(key, getClassName(), Activator.MESSAGE_PATH);
    }

    //temp fix for dx9
    @Override
    protected String wsVerifyPinSubmitHandle(Map model, HttpServletRequest request, HttpServletResponse response) throws IOException {
        UserSecurity us = DirectoryUtil.getUserSecurity();

        String tempusername = request.getParameter("u");
        if (tempusername != null) {
            UserMetaDataDao dao = (UserMetaDataDao) AppUtil.getApplicationContext().getBean("userMetaDataDao");

            String username = SecurityUtil.decrypt(tempusername);
            String nonce = request.getParameter("nonce");
            UserMetaData usecret = dao.getUserMetaData(username, KEY);

            if (usecret == null || !SecurityUtil.verifyNonce(nonce, new String[] {tempusername, usecret.getValue()})) {
                return getTemplate("unauthorized", model);
            }

            try {
                model.put("url", AppUtil.getRequestContextPath() + "/web/json/plugin/"+getClassName()+"/service?a=vps&u="+URLEncoder.encode(tempusername, "UTF-8")+"&nonce="+URLEncoder.encode(nonce, "UTF-8"));
            } catch (UnsupportedEncodingException ex) {
            }

            String pin = request.getParameter("pin");
            if (pin != null && pin.equals(getTOTPCode(SecurityUtil.decrypt(usecret.getValue())))) {
                return loginUser(username, request);
            } else {
                model.put("error", ResourceBundleUtil.getMessage("totp.invalid"));
            }
        }

        return getTemplate("verifyPin", model);
    }

    //temp fix for dx9
    public String loginUser (String username, HttpServletRequest request) throws IOException {
        ExtDirectoryManager dm = (ExtDirectoryManager) DirectoryUtil.getApplicationContext().getBean("directoryManager");
        User user = dm.getUserByUsername(username);

        Collection<Role> roles = dm.getUserRoles(username);
        List<GrantedAuthority> gaList = new ArrayList<GrantedAuthority>();
        if (roles != null && !roles.isEmpty()) {
            for (Role role : roles) {
                GrantedAuthority ga = new SimpleGrantedAuthority(role.getId());
                gaList.add(ga);
            }
        }

        // return result
        UserDetails details = new WorkflowUserDetails(user);
        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(user.getUsername(), "", gaList);
        result.setDetails(details);

        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(result);

        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);


        HttpServletRequest httpRequest = WorkflowUtil.getHttpServletRequest();
        String ip = AppUtil.getClientIp(httpRequest);
        LogUtil.info(getClass().getName(), "Authentication for user " + username + " ("+ip+") : true");
        WorkflowHelper workflowHelper = (WorkflowHelper) AppUtil.getApplicationContext().getBean("workflowHelper");
        workflowHelper.addAuditTrail(this.getClass().getName(), "authenticate", "Authentication for user " + username + " ("+ip+") : true");

        //post login processing
        UserSecurity userSecurity = DirectoryUtil.getUserSecurity();
        if (userSecurity != null) {
            userSecurity.loginPostProcessing(user, null, true);
        }

        return "<script>parent.window.location = '"+getRedirectUrl()+"';</script>";
    }
}
