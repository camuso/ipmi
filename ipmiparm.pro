TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    ipmiparm.cpp

INCLUDEPATH += $$PWD/
DEPENDPATH += $$PWD/

# boost system file manipulation libraries
#
#LIBS += -L/usr/local/lib/boost/     # boost library directory
#LIBS += -lboost_filesystem          # boost filesystem
#LIBS += -lboost_system              # boost system
    command.str("");
