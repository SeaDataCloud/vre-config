#!/bin/bash

#ps aux | grep '[f]ilebeat' || exit 1

if ps aux | grep '[f]ilebeat'; then
    exit 0
else
    exit 1
fi

# From:
#https://github.com/elastic/beats/issues/12665


