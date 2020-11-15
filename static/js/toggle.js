$(function(){
    $('.pic').click(function() {
        id = $(this).attr('id');
        let header = document.getElementById("header_" + id);
        let type = document.getElementById("type_" + id).value;
        let filename = document.getElementById("filename_" + id).value;
        let img_width = document.getElementById("width_" + id).value;
        let img_height = document.getElementById("height_" + id).value;
        let src_thumb = document.getElementById("src_thumb_" + id).value;
        let src_full = "/files/image/" + id + "/" + filename;
        if (type === "op") thumb_width = "250px"
        else if (type === "reply") thumb_width = "190px"

        if ($(this).attr('src') == src_full) {
            $(this).attr("src", "");
            $(this).attr("src", src_thumb);
            if (type === "op") new_width = "250px"
            else if (type === "reply") new_width = "190px"
            $(this).animate({width: new_width}, 0);
            header.className = "";
        }
        else if ($(this).attr('src') == src_thumb) {
            $(this).attr("src", "");
            $(this).attr("src", src_full);
            if (img_width > window.innerWidth) new_width = "98%";
            else new_width = img_width;
            $(this).animate({width: new_width}, 0);
            header.className = "header-inline-block";
        }
    });
});

$(function(){
    $('.video').click(function() {
        id = $(this).attr('id');
        let type = document.getElementById("type_" + id).value;
        current_width = $(this).css('width');
        let width = document.getElementById("width_" + id).value;
        let height = document.getElementById("height_" + id).value;
        if (type === "op") thumb_width = "250px"
        else if (type === "reply") thumb_width = "190px"
        if (current_width === thumb_width) {
            if (width > window.innerWidth) new_width = "98%";
            else new_width = width;
            $(this).animate({width: new_width}, 0);
        } else {
            $(this).animate({width: thumb_width}, 0);
        }
    });
});
