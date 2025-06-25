spicy_add_analyzer(
    NAME Genisys
    PACKAGE_NAME Genisys
    SOURCES zeek_analyzer.spicy
            enums.spicy
            analyzer.spicy
            analyzer.evt
    SCRIPTS __load__.zeek
)