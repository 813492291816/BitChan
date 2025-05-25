function refresh_captcha() {
    $.getJSON("/captcha/post_captcha/0/1",
        function(captcha, responseText, jqXHR) {
            if (jqXHR.status !== 204) {
                var captcha_update = document.getElementById('post_captcha');
                captcha_update.src = "data:image/png;base64, " + captcha['b64'];
                var page_id_update = document.getElementById('page_id');
                page_id_update.value = captcha['page_id'];
            }
            else {
                console.log("Captcha error: " + responseText);
            }
        }
    );
}

function send_post(form, form_data) {
    $.ajax({
        type: "GET",
        url: "/csrf/{{thread.chan.address}}",
        success: function (csrf_token) {

            form_data.set('csrf_token', csrf_token);

            $.ajax({
                type: "POST",
                enctype: 'multipart/form-data',
                url: "/thread/{{thread.chan.address}}/{{thread.thread_hash_short}}?ref=1",
                data: form_data,
                processData: false,
                contentType: false,
                cache: false,
                timeout: 800000,
                success: function (data) {

                    let output_str = '<a class="close_reply_return themed" href="#popup_reply" onclick="document.getElementById(\'reply_submit_output\').style.display = \'none\'">X</a> <span style="word-break: break-all" class="themed';
                    if ("status_title" in data) {
                        if (data.status_title === "Success" || data.status_title === "Preview") {
                            output_str += ' success">Success: ';
                        }
                        else if (data.status_title === "Error") {
                            output_str += ' error">Error: ';
                        }
                        else {
                            output_str += '">Unknown Status: ';
                        }
                    }
                    if ("status_message" in data) {
                        output_str += data.status_message.join("; ");
                    }
                    if ("preview" in data) {
                        document.getElementById("post_preview").style.display = '';
                        document.getElementById("post_preview_body").style.display = '';
                        $("#reply_submit_preview").html(data.preview);
                        if (document.getElementById('popup_captcha') != null) document.getElementById('popup_captcha').value = "";
                    }
                    output_str += '</span>';
                    $("#reply_submit_output").html(output_str);
                    $("#reply_submit_output").css("display", "initial")
                    $("#btn_preview_submit").prop("value", "Preview");
                    $("#btn_preview_submit").prop("disabled", false);
                    $("#btn_reply_submit").prop("value", "Post");
                    $("#btn_reply_submit").prop("disabled", false);

                    if ("status_title" in data && data.status_title === "Success" && !("preview" in data)) {
                        form.reset();

                        document.getElementById("post_preview").style.display = 'none';
                        document.getElementById("post_preview_body").style.display = 'none';

                        document.getElementById('image1').removeAttribute('src');
                        document.getElementById('image1_large').removeAttribute('src');

                        document.getElementById('image2').removeAttribute('src');
                        document.getElementById('image2_large').removeAttribute('src');

                        document.getElementById('image3').removeAttribute('src');
                        document.getElementById('image3_large').removeAttribute('src');

                        document.getElementById('image4').removeAttribute('src');
                        document.getElementById('image4_large').removeAttribute('src');
                    }

                    if (document.getElementById('popup_captcha') != null) refresh_captcha();

                },
                error: function (e) {

                    $("#reply_submit_output").text('Error: ' + e.responseText);
                    $("#reply_submit_output").css("display", "initial")
                    $("#btn_preview_submit").prop("value", "Preview");
                    $("#btn_preview_submit").prop("disabled", false);
                    $("#btn_reply_submit").prop("value", "Post");
                    $("#btn_reply_submit").prop("disabled", false);
                    if (document.getElementById('popup_captcha') != null) refresh_captcha();

                }
            });

        },
        error: function (e) {

            $("#reply_submit_output").text('Error: Could not get CSRF Token');
            $("#reply_submit_output").css("display", "initial")
            $("#btn_preview_submit").prop("value", "Preview");
            $("#btn_preview_submit").prop("disabled", false);
            $("#btn_reply_submit").prop("value", "Post");
            $("#btn_reply_submit").prop("disabled", false);
            if (document.getElementById('popup_captcha') != null) refresh_captcha();
        }
    });
}

function renameFile(originalFile, newName) {
    return new File([originalFile], newName, {
        type: originalFile.type
    });
}

$(document).ready(function() {
    $("#btn_preview_submit").click(function (event) {
        event.preventDefault();
        $("#reply_submit_output").html('');
        var form = $('#reply_form')[0];
        var form_data = new FormData(form);
        $("#btn_preview_submit").prop("disabled", true);
        $("#btn_reply_submit").prop("disabled", true);
        $("#btn_preview_submit").prop("value", "Wait...");

        form_data.append("preview_post", true);
        send_post(form, form_data);
    });

    $("#btn_reply_submit").click(function (event) {
        event.preventDefault();
        $("#reply_submit_output").html('');
        var form = $('#reply_form')[0];
        var form_data = new FormData(form);
        $("#btn_preview_submit").prop("disabled", true);
        $("#btn_reply_submit").prop("disabled", true);
        $("#btn_reply_submit").prop("value", "Wait...");

        send_post(form, form_data);
    });

    var post_update_init = document.getElementById('new-post-update-init');
    post_update_init.innerHTML = '/ <button onclick="reset_new_post_counter()">Update</button> Next Update: ';

    var post_update = document.getElementById('new-post-update');
    post_update.innerHTML = '...';

    var volume_set = document.getElementsByClassName("volume-75");
    if (volume_set.length > 0) {
        for(var i=0; i<=volume_set.length; i++) {
            if (volume_set[i] !== undefined) volume_set[i].volume = 0.75;
        }
    }

});

function randomString(id_field) {
    var characters = "ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz0123456789";
    var lenString = 32;
    var randomstring = '';

    for (var i=0; i<lenString; i++) {
        var rnum = Math.floor(Math.random() * characters.length);
        randomstring += characters.substring(rnum, rnum+1);
    }

    document.getElementById(id_field).value = randomstring;
    CopyToClipboard(randomstring);
}

function reply_link_to_comment(text_reply) {
    let myField = document.getElementById('post_body_reply_popup');
    if (myField.selectionStart || myField.selectionStart == '0') {
        var startPos = myField.selectionStart;
        var endPos = myField.selectionEnd;
        let str_value = myField.value.substring(0, startPos);
        str_value += '>>' + text_reply + '\n';
        if (window.getSelection().toString()) {
            let list_value = window.getSelection().toString().split(/\r?\n/)
            for (let i=0; i<list_value.length; i++) {
                str_value += '>' + list_value[i] + '\n';
            }
        }
        str_value += myField.value.substring(endPos, myField.value.length);
        myField.value = str_value;
    }
}
