package org.joget.marketplace;

import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.LogUtil;
import org.joget.directory.model.service.DirectoryManagerPlugin;
import org.joget.directory.model.service.UserSecurity;
import org.joget.directory.model.service.UserSecurityFactory;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.plugin.directory.dao.UserExtraDao;
import org.joget.plugin.directory.dao.UserPasswordHistoryDao;

import java.util.HashMap;
import java.util.Map;

public class MandatoryMfaSecureDirectoryManagerImpl extends SecureDirectoryManagerImpl implements UserSecurityFactory {

    private UserSecurity userSecurity;

    public static final Integer NUM_OF_DM = 1;
    private Map<String, Object> properties;
    private Map<Integer, DirectoryManagerPlugin> dmps;
    private Map<Integer, Map<String, Object>> dmpProperties;

    public MandatoryMfaSecureDirectoryManagerImpl(Map properties) {
        super(properties);
    }

    @Override
    public Map<String, Object> getProperties() {
        return this.properties;
    }

    @Override
    public void setProperties(Map<String, Object> properties) {
        this.properties = properties;
        this.dmps = new HashMap();
        this.dmpProperties = new HashMap();
        PluginManager pm = (PluginManager)AppUtil.getApplicationContext().getBean("pluginManager");

        for(int i = 1; i <= NUM_OF_DM; ++i) {
            try {
                Object dmObject = this.getProperty("dm" + i);
                if (dmObject != null && dmObject instanceof Map) {
                    Map temp = (Map)dmObject;
                    String className = temp.get("className").toString();
                    if (!className.isEmpty()) {
                        DirectoryManagerPlugin plugin = (DirectoryManagerPlugin)pm.getPlugin(className);
                        if (plugin != null) {
                            Map<String, Object> tempProperties = (Map)temp.get("properties");
                            this.dmps.put(i, plugin);
                            this.dmpProperties.put(i, tempProperties);
                        }
                    }
                }
            } catch (Exception e) {
                LogUtil.error(SecureDirectoryManagerImpl.class.getName(), e, "");
            }
        }

    }

    @Override
    public Object getProperty(String property) {
        Object value = this.properties != null ? this.properties.get(property) : null;
        return value;
    }

    @Override
    public String getPropertyString(String property) {
        String value = this.properties != null && this.properties.get(property) != null ? (String)this.properties.get(property) : "";
        return value;
    }

    @Override
    public void setProperty(String property, Object value) {
        if (this.properties == null) {
            this.properties = new HashMap();
        }

        this.properties.put(property, value);
    }

    /**
     * Override this method to return a custom UserSecurity object to customize the login form footer
     * @return 
     */
    @Override
    public UserSecurity getUserSecurity() {
        if (userSecurity == null) {
            userSecurity = new MandatoryMfaUserSecurityImpl();
            UserExtraDao userExtraDao = (UserExtraDao)AppUtil.getApplicationContext().getBean("userExtraDao");
            UserPasswordHistoryDao userPasswordHistoryDao = (UserPasswordHistoryDao)AppUtil.getApplicationContext().getBean("userPasswordHistoryDao");
            ((MandatoryMfaUserSecurityImpl)userSecurity).setUserExtraDao(userExtraDao);
            ((MandatoryMfaUserSecurityImpl)userSecurity).setUserPasswordHistoryDao(userPasswordHistoryDao);
        }
        Map<String, Object> usProperties = new HashMap<String, Object>();
        Map<String, Object> properties = getProperties();
        if (properties != null) {
            usProperties.putAll(properties);
        }
        if (dmps != null) {
            usProperties.put("_dmps", dmps);
            usProperties.put("_dmpProperties", dmpProperties);
        }
        userSecurity.setProperties(usProperties);
        return userSecurity;
    }
    
}

