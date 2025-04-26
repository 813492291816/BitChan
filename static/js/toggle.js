expanded_files = {};

function toggle_all_pics() {
    $('#body .pic').trigger('click');
}

$(function() {
    $("#toggle_images").click(function(e) {
        e.preventDefault();
        toggle_all_pics();
    });
});

$(function() {
    $('#body').on('click', '.pic', function() {
        post_id = $(this).attr('id').split('_')[1];
        index = $(this).attr('id').split('_')[2];
        let img = document.getElementById("img_" + post_id + "_" + index);
        let type = document.getElementById("type_" + post_id).value;
        let filename = document.getElementById("filename_" + post_id + "_" + index).value;
        let img_width = document.getElementById("width_" + post_id + "_" + index).value;
        let img_height = document.getElementById("height_" + post_id + "_" + index).value;
        let src_thumb = document.getElementById("src_thumb_" + post_id + "_" + index).value;
        let thumb_width = "";
        let thumb_height = "";
        if (document.getElementById("thumb_width_" + post_id + "_" + index) != null) thumb_width = document.getElementById("thumb_width_" + post_id + "_" + index).value;
        if (document.getElementById("thumb_height_" + post_id + "_" + index) != null) thumb_height = document.getElementById("thumb_height_" + post_id + "_" + index).value;
        let spoiler = document.getElementById("spoiler_" + post_id + "_" + index).value;
        let newline = document.getElementById("newline_" + post_id);
        let num_files = parseInt(document.getElementById("num_files_" + post_id).value);
        let truncate = document.getElementById("truncate_" + post_id).value;
        let src_full = "/files/image/" + post_id + "/" + filename;

        if ($(this).attr('src') == src_full) {
            $(this).attr("src", "");
            $(this).attr("src", src_thumb);
            if (type === "op") {
                new_height = "200px";
                new_width = "200px";
                $(this).animate({'max-width': new_width}, 0);
                $(this).animate({'max-height': new_height}, 0);
            }
            else if (type === "reply") {
                if (thumb_width && thumb_height) {
                    $(this).animate({'width': thumb_width}, 0);
                    $(this).animate({'height': thumb_height}, 0);
                }
                else {
                    new_height = "130px";
                    new_width = "130px";
                    $(this).animate({'max-width': new_width}, 0);
                    $(this).animate({'max-height': new_height}, 0);
                }
            }
            expanded_files[post_id] = expanded_files[post_id].filter(e => e !== post_id + "_" + index);
            if (expanded_files[post_id].length == 0 && num_files < 3 && truncate === "0") newline.style.display = "none";

        }
        else if ($(this).attr('src') == src_thumb) {
            img.style.height = null;
            $(this).attr("src", "");
            $(this).attr("src", src_full);
            if (img_width > window.innerWidth) {
                new_width = "98%";
                new_height = "98%";
            }
            else {
                new_width = img_width;
                new_height = img_height;
            }
            if (!(post_id in expanded_files)) expanded_files[post_id] = [];
            expanded_files[post_id].push(post_id + "_" + index);
            newline.style.display = "block";
            $(this).animate({'max-width': new_width}, 0);
            $(this).animate({'max-height': new_height}, 0);
            $(this).width('auto');
            $(this).height('auto');
        }
    });
});

function calc_resize(width, height, max_width, max_height) {
    if (width > max_width) {
        w_ratio = height / width;
        width = max_width;
        height = width * w_ratio;
    }
    if (height > max_height) {
        h_ratio = width / height;
        height = max_height;
        width = height * h_ratio;
    }
    return {'width': width, 'height': height};
}

$(function() {
    $('#body').on('click', '.video', function() {
        post_id = $(this).attr('id').split('_')[1];
        index = $(this).attr('id').split('_')[2];
        let type = document.getElementById("type_" + post_id).value;
        current_height = $(this).css('height');
        let thumb_width = document.getElementById("thumb_width_" + post_id + "_" + index).value;
        let thumb_height = document.getElementById("thumb_height_" + post_id + "_" + index).value;
        let width = document.getElementById("width_" + post_id + "_" + index).value;
        let height = document.getElementById("height_" + post_id + "_" + index).value;
        let num_files = parseInt(document.getElementById("num_files_" + post_id).value);
        let truncate = document.getElementById("truncate_" + post_id).value;
        let newline = document.getElementById("newline_" + post_id);

        console.log("Current: " + current_height + ", Thumb: " + thumb_height);

        if (current_height === thumb_height) {
            if (width > window.innerWidth) {
                calc_dim = calc_resize(width, height, window.innerWidth, window.innerHeight);
                new_width = calc_dim.width + "px";
                new_height = calc_dim.height + "px";
            }
            else {
                new_width = width + "px";
                new_height = (parseInt(height) + 20) + "px";
            }
            if (!(post_id in expanded_files)) expanded_files[post_id] = [];
            expanded_files[post_id].push(post_id + "_" + index);
            newline.style.display = "block";
            $(this).animate({width: new_width}, 0);
            $(this).animate({height: new_height}, 0);
        } else {
            expanded_files[post_id] = expanded_files[post_id].filter(e => e !== post_id + "_" + index);
            if (expanded_files[post_id].length == 0 && num_files < 3 && truncate === "0") newline.style.display = "none";
            $(this).animate({'width': thumb_width}, 0);
            $(this).animate({'height': thumb_height}, 0);
        }
    });
});
