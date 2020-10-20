#!/bin/bash

FILECONTENT=$(cat ishealthy.txt)
if  [[ $FILECONTENT == OK* ]] ; then
    echo $FILECONTENT;
    exit 0
else
    echo $FILECONTENT;
    exit 1
fi
