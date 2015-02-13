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
    echo "\tcopy $INSTALL/psuedonode..."
    cp pseudonode.linux $INSTALL/pseudonode
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
    echo "\tcopy $INSTALL/psuedonode..."
    cp pseudonode.macosx $INSTALL/pseudonode
    echo "\tcopy $INSTALL/libminiupnpc.so..."
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
    echo "\tcopy $INSTALL/psuedonode..."
    cp PseudoNode.exe $INSTALL
    echo "\tcopy $INSTALL/libminiupnpc.so..."
    cp miniupnpc.dll $INSTALL
    echo "\tbuilding $PACKAGE..."
    zip -r $PACKAGE $INSTALL > /dev/null
    echo -n "\tclean $INSTALL..."
    rm -rf $INSTALL
    echo "DONE"
fi

