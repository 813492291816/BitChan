var time_left = 0;
var timer = null;

function set_timer_sec(str_sec, show_unit = true) {
    let str_out = ""
    str_out += "TTP: " + str_sec
    if (show_unit) str_out += " s"
    document.getElementById("post-timer").innerHTML = str_out;
}

function stop_timer() {
    clearInterval(timer);
    timer = null;
}

function start_timer() {
    timer = setInterval(function() {
        if (time_left >= 0) {
            set_timer_sec(time_left);
            time_left -= 1;
        } else stop_timer();
    }, 1000);  // period is in ms
}

function get_post_timer(force_update = false) {
    const url = '/post-timer';
    $.getJSON(url,
        function(timer_resp, responseText, jqXHR) {
            if (jqXHR.status !== 204) {
                time_left = parseInt(timer_resp);
                if (force_update) set_timer_sec(time_left);
                if (timer_resp !== "0") {
                    if (timer === null) start_timer();
                } else {
                    stop_timer();
                }
            }
            else {
                stop_timer();
                set_timer_sec("...", false);
            }
        }
    );
}

function repeat_get_post_timer() {
    setInterval(function () {
        get_post_timer();
    }, 20000);  // period is in ms
}

$(document).ready(function() {
    set_timer_sec("...", false);
    get_post_timer(true);
    repeat_get_post_timer();
});
