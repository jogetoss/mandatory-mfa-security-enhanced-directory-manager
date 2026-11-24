---
breaks: false
---

# T8624 — Forgot Password signs the user in without MFA (Mandatory MFA SEDM)

***Revision 1** · published 2026-11-16 06:52 +00*

**Customer:** TMS SE (Sunway project) · **Product:** Joget DX 8.1.10 Enterprise (from linked T8191; T8624's version field is blank) · **DB:** MySQL · **OS:** Linux
**Plugin:** jogetoss `mandatory-mfa-security-enhanced-directory-manager` 8.0.1 (recommended in T8191)
**Investigated against:** joget-enterprise `8.1.10` (source), plus bytecode of `jw-enterprise-plugins` in the official `8.2.13` and `9.1.2.2` images; plugin tag `8.0.1`.
Latest tags today: DX8 8.2.13.1, DX9 9.1.2.2.

## Short answer

This is how core SEDM works, not a plugin misconfiguration. The change-password submit (`?a=cps`) deliberately skips the MFA check and then logs the user straight in. Forgot Password uses that same submit, so the user ends up logged in with no OTP. It is unchanged up to 8.2.13 and 9.1.2.2, and nothing in the change logs or Known Issues mentions it.

There is no setting that turns it off. The customer already runs (and forks) the jogetoss Mandatory MFA plugin, so the practical fix is a small override in that plugin. It ends the session after the password change and sends the user back to the login page, where MFA applies. Patch below.

## What actually happens

1. **Forgot Password email**: `forgotPassword()` creates a temp password + token and emails both. The default template is `"Your temporary password is #password#. Please change your password using the link below: #changePasswordUrl#"`.
   - `UserSecurityImpl.java:1365` @ 8.1.10, `eplugin.properties:1513` @ 8.1.10
2. **Link opens the change-password popup** (`a=fpcp`), and the form posts to **`?a=cps`** (`templates/changePassword.ftl`).
3. **`wsChangePasswordSubmitHandle()`** (`UserSecurityImpl.java:1153` @ 8.1.10) checks the temp password, then calls `loginPostProcessing(user, …, loggedIn)` (`:1193`).
4. **`loginPostProcessing()` skips MFA when `a=cps`**:
   ```java
   // UserSecurityImpl.java:643-649 @ 8.1.10
   if (loggedIn && !isProfileUpdate && getMfaAuthenticator() != null
           && getMfaAuthenticator().isOtpRequired(user.getUsername())
           && !(request != null && "cps".equals(request.getParameter("a")))   // <-- exemption
           && ...) {
       ... validateOtpUrl popup + throw  // the normal MFA prompt
   }
   ```
5. After saving the new password, the same handler **logs the user in directly**: `SecurityContextHolder.getContext().setAuthentication(result)` (`:1259` @ 8.1.10), then redirects to the original page.
   - DX9 does the same with `UserAuthenticationService.getInstance().loginUser(user)`.

The plugin doesn't change this. `MandatoryMfaUserSecurityImpl.loginPostProcessing()` has the same `a=cps` exemption for forced enrolment (`MandatoryMfaUserSecurityImpl.java:63` @ 8.0.1). For users who are already enrolled, it hands off to `super.loginPostProcessing()` (`:72`), which is step 4.

The next normal login goes through `/j_spring_security_check`, not `cps`, so MFA comes back. That matches what the customer sees.

**The expired-password path has the same gap.** On a normal login, `authenticatePasswordExpired()` runs before the MFA check and opens the same `cp`→`cps` popup (`:638-639`, `:1558-1563` @ 8.1.10). A user whose password is expired or flagged "must change" therefore also finishes login without OTP. The ticket doesn't mention this, but the patch below covers it too.

### Versions checked

| Version | `a=cps` MFA exemption | direct login after cps |
|---|---|---|
| 8.1.10 (source) | yes, `:645` | `setAuthentication`, `:1259` |
| 8.2.10 (source) | yes, `:645` | `setAuthentication`, `:1264` |
| 8.2.13 (image bytecode) | yes | `SecurityContext.setAuthentication` |
| 9.0.7 / 9.1-PREVIEW2 (source) | yes | `UserAuthenticationService.loginUser` |
| 9.1.2.2 (image bytecode) | yes | `UserAuthenticationService.loginUser` |

`CHANGES.txt` in the 8.2.13 and 9.1.2.2 images has no entry for this. KB DX8 *Forgot Password Feature* and the marketplace *Mandatory MFA SEDM* article don't mention it.

## Impact

- **Security, not cosmetic.** Whoever can read the user's mailbox gets a full session, because the email holds both the link and the temp password. MFA is meant to stop exactly that.
- Same for anyone who knows an expired password.
- No data loss. The bypass lasts one session only.

## Fix / workaround

**For the customer (they already maintain a fork of the plugin, per T8191):** override `wsChangePasswordSubmitHandle` in `MandatoryMfaUserSecurityImpl`. Let core save the password, then end the session it just created and send the user to `/web/login`. MFA (or forced enrolment) then runs as normal.

```java
// add to org.joget.marketplace.MandatoryMfaUserSecurityImpl
// imports: java.util.Map, javax.servlet.http.HttpServletResponse,
//          javax.servlet.http.HttpSession,
//          org.springframework.security.core.context.SecurityContextHolder
@Override
protected String wsChangePasswordSubmitHandle(Map model, HttpServletRequest request, HttpServletResponse response) {
    String content = super.wsChangePasswordSubmitHandle(model, request, response);

    if ("true".equals(model.get("updated")) && getMfaAuthenticator() != null) {
        SecurityContextHolder.clearContext();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        content = "<script>parent.window.location = '" + request.getContextPath() + "/web/login';</script>";
    }
    return content;
}
```

- Full diff against plugin tag 8.0.1: `evidence/mandatory-mfa-force-relogin.patch`.
- **Status: compiles against the DX 8.1.10 jars. Not yet tested at runtime.** Before sending, test it on a `jogetman` 8.1.10 env with SMTP: Forgot Password, then the expired-password case.
- What the user sees: after setting the new password they are sent to the login page instead of straight into the app. They sign in with the new password and get the OTP prompt. The page they were trying to reach is lost.
- On DX9 the same code works with `jakarta.servlet.*` imports.

**For product:** raise this as an SEDM bug. Core should not skip MFA and auto-login after a `cps` submit when the user has MFA enrolled. It should either require OTP or send the user back to login. Reference this ticket.

## Draft reply to customer

> Hi Paul,
>
> Thanks for the clear steps. We checked and this comes from the Security Enhanced Directory Manager itself: after a password change through Forgot Password, it signs the user in directly and skips the MFA prompt. The same happens when a user changes an expired password. There's no setting to change this, and it is the same in the latest DX8 and DX9 releases. We've raised it with our product team.
>
> Since you already maintain your own build of the Mandatory MFA SEDM plugin, you can close the gap there. Add the method below to `MandatoryMfaUserSecurityImpl`. After the password is changed, it ends that session and sends the user back to the login page, so they log in with the new password and enter their MFA code.
>
> *(paste the override above)*
>
> Please test it in UAT first. Note that JogetOSS plugins are community-supported and outside Enterprise Support scope.
>
> Regards

## Evidence

- `joget-enterprise jw-enterprise/wflow-enterprise-plugins/src/main/java/org/joget/plugin/directory/UserSecurityImpl.java` @ 8.1.10:
  - lines 630–650 (`loginPostProcessing`, cps exemption at 645)
  - 1153–1275 (`wsChangePasswordSubmitHandle`; forgot-password branch 1177–1196, auto-login 1253–1259)
  - 1365 (`forgotPassword`)
  - 1558–1563 (`authenticatePasswordExpired` cps skip)
- `…/resources/templates/changePassword.ftl` @ 8.1.10: `<form action="?a=cps">`
- `jw-enterprise/wflow-enterpriseweb/src/main/resources/eplugin.properties:1513` @ 8.1.10: email carries `#password#` and `#changePasswordUrl#`
- `jogetoss/mandatory-mfa-security-enhanced-directory-manager` @ 8.0.1: `MandatoryMfaUserSecurityImpl.java:39-76`
- `javap -c` of `org.joget.plugin.directory.UserSecurityImpl` from `jw-enterprise-plugins-8.2.13.jar` and `-9.1.2.2.jar` (official images): `"cps"` constant still used in `loginPostProcessing`; cps handler still logs in directly
- Related: T8191 (same customer, how Mandatory MFA was set up)
