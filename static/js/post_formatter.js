function lbc(h, a, i) {
    var g = document.getElementById(h);
    g.focus();
    if (g.setSelectionRange) {
        var c = g.scrollTop;
        var e = g.selectionStart;
        var f = g.selectionEnd;
        g.value = g.value.substring(0, g.selectionStart) + a + g.value.substring(g.selectionStart, g.selectionEnd) + i + g.value.substring(g.selectionEnd, g.value.length);
        g.selectionStart = e;
        g.selectionEnd = f + a.length + i.length;
        g.scrollTop = c;
    } else {
        if (document.selection && document.selection.createRange) {
            g.focus();
            var b = document.selection.createRange();
            if (b.text != "") {
                b.text = a + b.text + i;
            } else {
                b.text = a + "REPLACE" + i;
            }
            g.focus();
        }
    }
}
