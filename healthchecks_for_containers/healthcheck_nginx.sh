#!/bin/bash

#service nginx status || exit 1


if service nginx status; then
    exit 0
else
    exit 1
fi

# Cannot use curl, as curl is not installed on nginx image!

