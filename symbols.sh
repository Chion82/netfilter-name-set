#!/bin/sh
MODULE_NAME=xt_nameset
MODULE_FILENAME=${MODULE_NAME}.ko
MODULE_FILE=$(modinfo $MODULE_FILENAME| awk '/filename/{print $2}')
DIR="/sys/module/${MODULE_NAME}/sections/"
echo add-symbol-file $MODULE_FILE $(cat "$DIR/.text") -s .bss $(cat "$DIR/.bss") -s .data $(cat "$DIR/.data")
