<style>
    body.popupBody #main-body-header{
        text-align: center;
        position: relative;
        padding: 0;
        background: none;
        color: #000;
    }

    body.popupBody #main-body-content{
        height: 100% !important;
    }

    form.form fieldset {
        background-clip: border-box;
        border: 1px solid rgba(0, 0, 0, .06);
        border-radius: 0.25rem;
        padding-bottom: 20px;
        max-width: 400px;
        margin: auto;
    }

    form.form fieldset .form-row:first-child {
        margin-top: 20px;
    }

    form.form fieldset .form-row {
        padding-left: 20px;
        padding-right: 20px;
        position: relative;
        display: flex;
        flex-direction: column;
    }

    form.form fieldset .form-row > label {
        white-space: normal;
        position: relative;
        flex: 0 0 30%;
        margin-bottom: 0px;
        padding: 8px 10px 0 0;
        min-height: 34px;
        font-weight: 400;
        width: 100%;
    }

    .form-row .form-input{
        margin: 0;
    }

    .form-row input[type=text]{
        width: 100%;
    }

    label[for=secret], .barcode-section, .secret-section{
        text-align: center;
    }

    .secret-container{
        font-weight: bold;
    }

    input[type='submit']{
        width: 100%;
    }
</style>

<div id="main-body-header">
    @@totp.enable@@
</div>
<div id="main-body-content">
    <#if updated! == "true">
        <p>@@totp.activated@@</p>
    <#else>
        <form id="enableTotpAuth" action="${url!}" class="form" method="POST">
            <fieldset>

                <#if error??>
                    <div class="form-errors">
                        ${error!}
                    </div>
                </#if>

                <div class="form-row">
                    <label for="secret">@@totp.enable.description@@</label>
                    <div class="barcode-section">
                        <img src="${barcodeUrl!}"/>
                    </div>
                    <div class="secret-section">
                        <div>@@totp.secret.description@@</div>
                        <div class="secret-container">${secret!}</div>
                    </div>
                    <input id="secret" name="secret" type="hidden" value="${secret!}"/>
                </div>
                <div class="form-row">
                    <label for="pin">@@totp.pin@@ *</label>
                    <span class="form-input"><input id="pin" name="pin" type="text" value=""/></span>
                </div>
                <div class="form-row">
                    <input class="form-button btn button" type="submit" value="Submit">
                </div>
            </fieldset>
        </form>
    </#if>
</div>

<script>
    $(parent.document).find('.ui-front').css({
        cssText: 'max-width: 100vw !important',
        height: '100vh',
        width: '100vw',
        position: 'fixed',
        top: 0,
        left: 0,
        border: 'none',
        padding: 0,
    });
    $(parent.document).find('#jqueryDialogDiv').css({
        height: '100%',
        width: '100%',
    });
    $(parent.document).find('.ui-dialog-titlebar-close').hide();
    setTimeout(function(){
        $(parent.document).find('#jqueryDialogFrame').attr('height', '100%');
    }, 100);
</script>