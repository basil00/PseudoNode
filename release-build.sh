#!/bin/bash

set -e

VERSION=`cat ./VERSION`
NAME=PseudoNode-$VERSION

if [ -e pseudonode.linux ]
then
    echo "BUILD $NAME-Linux"
    INSTALL=$NAME-Linux
    PACKAGE=$NAME-Linux.zip
    echo "\tdelete $PACKAGE..."
    rm -f $PACKAGE
    echo "\tmake $INSTALL..."
    mkdir -p $INSTALL
    echo "\tcopy $INSTALL/LICENSE.txt..."
    cp LICENSE.txt $INSTALL
    echo "\tcopy $INSTALL/README.md..."
    cp README.md $INSTALL
    echo "\tcopy $INSTALL/pseudonode..."
    cp pseudonode.linux $INSTALL/pseudonode
    echo "\tcopy $INSTALL/libpseudonode.so..."
    cp libpseudonode.so $INSTALL
    echo "\tcopy $INSTALL/libminiupnpc.so..."
    cp libminiupnpc.so $INSTALL
    echo "\tbuilding $PACKAGE..."
    zip -r $PACKAGE $INSTALL > /dev/null
    echo -n "\tclean $INSTALL..."
    rm -rf $INSTALL
    echo "DONE"
fi

if [ -e pseudonode.macosx ]
then
    echo "BUILD $NAME-MacOSX"
    INSTALL=$NAME-MacOSX
    PACKAGE=$NAME-MacOSX.zip
    echo "\tdelete $PACKAGE..."
    rm -f $PACKAGE
    echo "\tmake $INSTALL..."
    mkdir -p $INSTALL
    echo "\tcopy $INSTALL/LICENSE.txt..."
    cp LICENSE.txt $INSTALL
    echo "\tcopy $INSTALL/README.md..."
    cp README.md $INSTALL
    echo "\tcopy $INSTALL/pseudonode..."
    cp pseudonode.macosx $INSTALL/pseudonode
    echo "\tcopy $INSTALL/libpseudonode.dylib..."
    cp libpseudonode.dylib $INSTALL
    echo "\tcopy $INSTALL/libminiupnpc.dylib..."
    cp libminiupnpc.dylib $INSTALL
    echo "\tbuilding $PACKAGE..."
    zip -r $PACKAGE $INSTALL > /dev/null
    echo -n "\tclean $INSTALL..."
    rm -rf $INSTALL
    echo "DONE"
fi

if [ -e PseudoNode.exe ]
then
    echo "BUILD $NAME-Windows"
    INSTALL=$NAME-Windows
    PACKAGE=$NAME-Windows.zip
    echo "\tdelete $PACKAGE..."
    rm -f $PACKAGE
    echo "\tmake $INSTALL..."
    mkdir -p $INSTALL
    echo "\tcopy $INSTALL/LICENSE.txt..."
    cp LICENSE.txt $INSTALL
    echo "\tcopy $INSTALL/README.md..."
    cp README.md $INSTALL
    echo "\tcopy $INSTALL/PseudoNode.exe..."
    cp PseudoNode.exe $INSTALL
    echo "\tcopy $INSTALL/miniupnpc.dll..."
    cp miniupnpc.dll $INSTALL
    echo "\tbuilding $PACKAGE..."
    zip -r $PACKAGE $INSTALL > /dev/null
    echo -n "\tclean $INSTALL..."
    rm -rf $INSTALL
    echo "DONE"
fi

VERSION=0.1
NAME=TxMon-$VERSION

if [ -e apps/txmon/txmon.linux ]
then
    echo "BUILD $NAME-Linux"
    INSTALL=$NAME-Linux
    PACKAGE=$NAME-Linux.zip
    echo "\tdelete $PACKAGE..."
    rm -f $PACKAGE
    echo "\tmake $INSTALL..."
    mkdir -p $INSTALL
    echo "\tcopy $INSTALL/LICENSE.txt..."
    cp LICENSE.txt $INSTALL
    echo "\tcopy $INSTALL/txmon..."
    cp apps/txmon/txmon.linux $INSTALL/txmon
    echo "\tcopy $INSTALL/libpseudonode.so..."
    cp libpseudonode.so $INSTALL
    echo "\tcopy $INSTALL/libminiupnpc.so..."
    cp libminiupnpc.so $INSTALL
    echo "\tbuilding $PACKAGE..."
    zip -r $PACKAGE $INSTALL > /dev/null
    echo -n "\tclean $INSTALL..."
    rm -rf $INSTALL
    echo "DONE"
fi

if [ -e apps/txmon/txmon.macosx ]
then
    echo "BUILD $NAME-MacOSX"
    INSTALL=$NAME-MacOSX
    PACKAGE=$NAME-MacOSX.zip
    echo "\tdelete $PACKAGE..."
    rm -f $PACKAGE
    echo "\tmake $INSTALL..."
    mkdir -p $INSTALL
    echo "\tcopy $INSTALL/LICENSE.txt..."
    cp LICENSE.txt $INSTALL
    echo "\tcopy $INSTALL/txmon..."
    cp apps/txmon/txmon.macosx $INSTALL/txmon
    echo "\tcopy $INSTALL/libpseudonode.dynlib..."
    cp libpseudonode.dynlib $INSTALL
    echo "\tcopy $INSTALL/libminiupnpc.dynlib..."
    cp libminiupnpc.dynlib $INSTALL
    echo "\tbuilding $PACKAGE..."
    zip -r $PACKAGE $INSTALL > /dev/null
    echo -n "\tclean $INSTALL..."
    rm -rf $INSTALL
    echo "DONE"
fi

if [ -e apps/txmon/TxMon.exe ]
then
    echo "BUILD $NAME-Windows"
    INSTALL=$NAME-Windows
    PACKAGE=$NAME-Windows.zip
    echo "\tdelete $PACKAGE..."
    rm -f $PACKAGE
    echo "\tmake $INSTALL..."
    mkdir -p $INSTALL
    echo "\tcopy $INSTALL/LICENSE.txt..."
    cp LICENSE.txt $INSTALL
    echo "\tcopy $INSTALL/TxMon.exe..."
    cp apps/txmon/TxMon.exe $INSTALL
    echo "\tcopy $INSTALL/PseudoNode.dll..."
    cp PseudoNode.dll $INSTALL
    echo "\tcopy $INSTALL/miniupnpc.dll..."
    cp miniupnpc.dll $INSTALL
    echo "\tbuilding $PACKAGE..."
    zip -r $PACKAGE $INSTALL > /dev/null
    echo -n "\tclean $INSTALL..."
    rm -rf $INSTALL
    echo "DONE"
fi

if [ -e apps/txmon/TxMon.exe ]
then
    echo "BUILD $NAME-Windows"
    INSTALL=$NAME-Windows
    PACKAGE=$NAME-Install.exe
    echo "\tdelete $PACKAGE..."
    rm -f $PACKAGE
    echo "\tmake $INSTALL..."
    mkdir -p $INSTALL
    echo "\tcopy $INSTALL/LICENSE.txt..."
    cp LICENSE.txt $INSTALL
    echo "\tcopy $INSTALL/TxMon.exe..."
    cp apps/txmon/TxMon.exe $INSTALL
    echo "\tcopy $INSTALL/PseudoNode.dll..."
    cp PseudoNode.dll $INSTALL
    echo "\tcopy $INSTALL/miniupnpc.dll..."
    cp miniupnpc.dll $INSTALL
    echo "\tbuilding $PACKAGE..."
    cd $INSTALL
    cp ../apps/txmon/install.nsi .
    makensis install.nsi
    mv TxMon-install.exe ../$PACKAGE
    echo -n "\tclean $INSTALL..."
    rm -rf $INSTALL
    echo "DONE"
fi

