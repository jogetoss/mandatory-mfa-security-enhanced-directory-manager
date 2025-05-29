package org.joget.marketplace;

import org.joget.apps.app.service.AppPluginUtil;
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
