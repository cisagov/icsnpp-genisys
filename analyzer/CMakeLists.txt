spicy_add_analyzer(
    NAME Genisys
    PACKAGE_NAME Genisys
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig)
