spicy_add_analyzer(
    NAME Genisys
    PACKAGE_NAME Genisys
    SOURCES zeek_analyzer.spicy
            enums.spicy
            analyzer.spicy
            analyzer.evt
    SCRIPTS ${CMAKE_SOURCE_DIR}/scripts/__load__.zeek
            ${CMAKE_SOURCE_DIR}/scripts/enums.zeek
            ${CMAKE_SOURCE_DIR}/scripts/main.zeek
)