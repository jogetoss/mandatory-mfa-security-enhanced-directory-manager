package org.joget.marketplace;

import org.joget.apps.app.service.AppPluginUtil;
import org.joget.commons.util.StringUtil;
import org.joget.directory.model.service.DirectoryManager;
import org.joget.plugin.directory.SecureDirectoryManager;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;

import java.util.*;

public class MandatoryMfaSecurityEnhancedDirectoryManager extends SecureDirectoryManager {

    public SecureDirectoryManagerImpl dirManager;

    @Override
    public String getName() {
        return getMessage("mmsedm.name");
    }

    @Override
    public String getLabel() {
        return getMessage("mmsedm.label");
    }

    @Override
    public String getDescription() {
        return getMessage("mmsedm.description");
    }

    @Override
    public String getVersion() {
        return getMessage("mmsedm.version");
    }

    /**
     * The standard Security Enhanced Directory Manager builds its settings from its own
     * UserSecurity, so the extra setting has to be added to the combined JSON here.
     */
    @Override
    public String getPropertyOptions() {
        String options = super.getPropertyOptions();

        String page = "{"
                + "title : '" + js(getMessage("mmsedm.mfaAfterReset.title")) + "',"
                + "properties : [{"
                + "name : '" + MandatoryMfaUserSecurityImpl.PROP_MFA_AFTER_PASSWORD_RESET + "',"
                + "label : '" + js(getMessage("mmsedm.mfaAfterReset.label")) + "',"
                + "description : '" + js(getMessage("mmsedm.mfaAfterReset.description")) + "',"
                + "type : 'checkbox',"
                + "options : [{ value : 'true', label : '' }]"
                + "}]"
                + "}";

        // place it before the "External Directory Manager" page, or at the end if that page is not found
        int marker = options.indexOf("@@app.edm.label.addonDirectorManager@@");
        int insertAt = marker >= 0 ? options.lastIndexOf('{', marker) : -1;
        if (insertAt < 0) {
            insertAt = options.lastIndexOf(']');
            if (insertAt < 0) {
                return options;
            }
            return options.substring(0, insertAt) + "," + page + options.substring(insertAt);
        }
        return options.substring(0, insertAt) + page + "," + options.substring(insertAt);
    }

    private String js(String value) {
        return StringUtil.escapeString(value, StringUtil.TYPE_JAVASCIPT, null);
    }

    @Override
    public DirectoryManager getDirectoryManagerImpl(Map properties) {
        if (dirManager == null) {
            dirManager = new MandatoryMfaSecureDirectoryManagerImpl(properties);
        } else {
            dirManager.setProperties(properties);
        }

        return dirManager;
    }

    protected String getMessage(String key) {
        return AppPluginUtil.getMessage(key, getClassName(), Activator.MESSAGE_PATH);
    }
}
