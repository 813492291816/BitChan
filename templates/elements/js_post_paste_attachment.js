let img_extensions = {{config.FILE_EXTENSIONS_IMAGE|safe}};

function isImage(string) {
    for (let suffix of img_extensions) {
        if(string.toLowerCase().endsWith("." + suffix.toLowerCase()))
            return true;
    }
    return false;
}

function randS(length) {
    const chars = '0123456789abcdefghijklmnopqrstuvwxyz';
    var result = '';
    for (var i = length; i > 0; --i) result += chars[Math.round(Math.random() * (chars.length - 1))];
    return result;
}

$(document).ready(function() {

    // if file input changes, and is image, set content of image elements
    document.getElementById('file1').onchange = function () {
        if (isImage(this.files[0].name)) {
            var src = URL.createObjectURL(this.files[0])
            document.getElementById('image1').src = src
            document.getElementById('image1_large').src = src
        }
    }
    document.getElementById('file2').onchange = function () {
        if (isImage(this.files[0].name)) {
            var src = URL.createObjectURL(this.files[0])
            document.getElementById('image2').src = src
            document.getElementById('image2_large').src = src
        }
    }
    document.getElementById('file3').onchange = function () {
        if (isImage(this.files[0].name)) {
            var src = URL.createObjectURL(this.files[0])
            document.getElementById('image3').src = src
            document.getElementById('image3_large').src = src
        }
    }
    document.getElementById('file4').onchange = function () {
        if (isImage(this.files[0].name)) {
            var src = URL.createObjectURL(this.files[0])
            document.getElementById('image4').src = src
            document.getElementById('image4_large').src = src
        }
    }

    // attach file by pasting from clipboard
    window.addEventListener('paste', e => {
        if (e.clipboardData.files.length == 1) {
            var fileInput1 = document.getElementById("file1");
            var fileInput2 = document.getElementById("file2");
            var fileInput3 = document.getElementById("file3");
            var fileInput4 = document.getElementById("file4");

            // Make list of attached file names
            let filenames_attached = [];
            if (fileInput1.value) filenames_attached.push(fileInput1.value);
            if (fileInput2.value) filenames_attached.push(fileInput2.value);
            if (fileInput3.value) filenames_attached.push(fileInput3.value);
            if (fileInput4.value) filenames_attached.push(fileInput4.value);

            var file_list = new DataTransfer();
            var file_attach;
            var filename = e.clipboardData.files[0].name;

            filename = randS(64) + ".png";  // Generate unique filename
            let file = renameFile(e.clipboardData.files[0], filename);
            file_list.items.add(file);
            file_attach = file_list.files;

            // set file input to clipboard contents
            // if image, set content of image elements
            if (!fileInput1.value) {
                fileInput1.files = file_attach;
                if (isImage(fileInput1.value)) {
                    document.getElementById('image1').src = URL.createObjectURL(file_attach[0])
                    document.getElementById('image1_large').src = URL.createObjectURL(file_attach[0])
                }
            }
            else if (!fileInput2.value) {
                fileInput2.files = file_attach;
                if (isImage(fileInput2.value)) {
                    document.getElementById('image2').src = URL.createObjectURL(file_attach[0])
                    document.getElementById('image2_large').src = URL.createObjectURL(file_attach[0])
                }
            }
            else if (!fileInput3.value) {
                fileInput3.files = file_attach;
                if (isImage(fileInput3.value)) {
                    document.getElementById('image3').src = URL.createObjectURL(file_attach[0])
                    document.getElementById('image3_large').src = URL.createObjectURL(file_attach[0])
                }
            }
            else if (!fileInput4.value) {
                fileInput4.files = file_attach;
                if (isImage(fileInput4.value)) {
                    document.getElementById('image4').src = URL.createObjectURL(file_attach[0])
                    document.getElementById('image4_large').src = URL.createObjectURL(file_attach[0])
                }
            }
        }
    });
});
