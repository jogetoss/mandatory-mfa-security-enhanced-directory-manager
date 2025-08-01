# Description

The Mandatory MFA Security Enhanced Directory Manager plugin extends the default [SEDM](https://dev.joget.org/community/display/DX8/Security+Enhanced+Directory+Manager) plugin by requiring users to activate MFA upon logging in, when configured with a compatible mandatory MFA authenticator.

You can customize this plugin to include additional logic for determining whether the current user is required to activate MFA by modifying the [`loginPostProcessing` method in the `MandatoryMfaUserSecurityImpl` class](https://github.com/jogetoss/mandatory-mfa-security-enhanced-directory-manager/blob/b33df2fc15f93e75153a6abcd52acee8824561f0/src/main/java/org/joget/marketplace/MandatoryMfaUserSecurityImpl.java#L49)

To setup and configure this plugin, please see the [documentation](https://dev.joget.org/community/display/SANDBOX2/Mandatory+MFA+Security+Enhanced+Directory+Manager).

# Getting Help

JogetOSS is a community-led team for open source software related to the [Joget](https://www.joget.org) no-code/low-code application platform.
Projects under JogetOSS are community-driven and community-supported.
To obtain support, ask questions, get answers and help others, please participate in the [Community Q&A](https://answers.joget.org/).

Note: When building the plugin, if you encounter the error below:

    The POM for org.joget:wflow-enterprise-plugins:jar:8.0-SNAPSHOT is missing, no dependency information available

    Failed to execute goal on project record-locking-form-element: Could not resolve dependencies for project org.joget.marketplace:mandatory-mfa-security-enhanced-directory-manager:bundle:8.0.0: Could not find artifact org.joget:wflow-enterprise-plugins:jar:8.0-SNAPSHOT -> [Help 1]

To obtain this jar, you will need to find it in the extracted jw.war folder. You can also find it in your joget installation /jw/WEB-INF/lib directory. Please run the following command to install the dependencies.

    mvn install:install-file -Dfile=jw-enterprise-plugins-8.1.12.jar -DgroupId=org.joget -DartifactId=wflow-enterprise-plugins -Dversion=8.0-SNAPSHOT -Dpackaging=jar -DgeneratePom=true
*Take note of the version (jw-enterprise-plugins-8.1.12.jar), and make sure you change it to your respective version.

# Contributing

This project welcomes contributions and suggestions, please open an issue or create a pull request.

Please note that all interactions fall under our [Code of Conduct](https://github.com/jogetoss/repo-template/blob/main/CODE_OF_CONDUCT.md).

# Licensing

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

NOTE: This software may depend on other packages that may be licensed under different open source licenses.
