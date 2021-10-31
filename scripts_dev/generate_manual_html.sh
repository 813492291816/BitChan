#!/bin/bash
# Dependencies:
# sudo apt install pandoc

SOURCE="${BASH_SOURCE[0]}"
LOC="$(cd -P "$(dirname "$SOURCE")/.." && pwd)"

pandoc "${LOC}"/MANUAL.md -o "${LOC}"/templates/pages/manual.html

sed -i 's/<!-- Replace with text formatting -->/{% include \x27\/pages\/help_text_formatting.html\x27 %}/g' "${LOC}"/templates/pages/manual.html
sed -i 's/<!-- Replace with text functions -->/{% include \x27\/pages\/help_text_functions.html\x27 %}/g' "${LOC}"/templates/pages/manual.html
