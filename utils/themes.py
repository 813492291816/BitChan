class DarkTheme:
    def __init__(self):
        self.gradient_top = "#000000"
        self.bgcolor = "#333333"
        self.textcolor = "#DDDDDD"
        self.divborder = "#000000"
        self.poster = "#888888"
        self.postbg = "#444444"
        self.posthilight = "#222222"
        self.link = "#ADD8E6"
        self.linkhilight = "#AAAAAA"
        self.themedtext = "#997052"
        self.subject = "#AAAAAA"
        self.formbg = "#444444"
        self.greentext = "#789922"
        self.greytext = "#707070"


class ClassicTheme:
    def __init__(self):
        self.gradient_top = "#FFD6AC"
        self.bgcolor = "#FFFFED"
        self.textcolor = "#820000"
        self.divborder = "#D9BFB7"
        self.poster = "#047841"
        self.postbg = "#F0E0D6"
        self.posthilight = "#F1C0AF"
        self.link = "#000082"
        self.linkhilight = "#CE0B00"
        self.themedtext = "#997052"
        self.subject = "#CE0B00"
        self.formbg = "#EA8"
        self.greentext = "#789922"
        self.greytext = "#707070"


class BlueTheme:
    def __init__(self):
        self.gradient_top = "#D1D5EF"
        self.bgcolor = "#EEF2FF"
        self.textcolor = "#000000"
        self.divborder = "#B7C5DA"
        self.poster = "#047841"
        self.postbg = "#D6DAF1"
        self.posthilight = "#D7C9D1"
        self.link = "#2F2C9C"
        self.linkhilight = "#0E065F"
        self.themedtext = "#997052"
        self.subject = "#0E065F"
        self.formbg = "#9985F1"
        self.greentext = "#789922"
        self.greytext = "#707070"


themes = {"Dark": DarkTheme(), "Classic": ClassicTheme(), "Frosty": BlueTheme()}
