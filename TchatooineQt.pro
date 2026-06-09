QT       += core gui network sql multimedia multimediawidgets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++23

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

INCLUDEPATH += /usr/include/miniupnpc\
        /usr/include/

win32:INCLUDEPATH += D:\EtienneArea\Personnel\miniupnp\miniupnpc\include\

SOURCES += \
    client.cpp \
    connexion.cpp \
    imagesettings.cpp \
    main.cpp \
    mainwindow.cpp \
    metadatadialog.cpp \
    serveuravecupnp.cpp \
    tchat.cpp \
    dbmanager.cpp \
    upnpmanager.cpp \
    videoencoder.cpp \
    videosettings.cpp

HEADERS += \
    client.h \
    connexion.h \
    imagesettings.h \
    mainwindow.h \
    metadatadialog.h \
    serveuravecupnp.h \
    tchat.h \
    dbmanager.h \
    upnpmanager.h \
    videoencoder.h \
    videosettings.h

FORMS += \
    imagesettings.ui \
    mainwindow.ui \
    videosettings.ui \
    videosettings_mobile.ui
win32:LIBS += -LD:\EtienneArea\Personnel\miniupnp\miniupnpc\build\Desktop_Qt_6_11_0_MinGW_64_bit-Debug
LIBS += -lminiupnpc
#sudo apt install libavcodec-dev libavutil-dev libswscale-dev

LIBS += -lavcodec
LIBS += -lavutil
LIBS += -lswscale

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
	resources.qrc
