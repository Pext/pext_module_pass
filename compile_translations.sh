#!/bin/sh

for dir in locale/*/LC_MESSAGES; do
    msgfmt "$dir/pext_module_pass.po" -o "$dir/pext_module_pass.mo"
done
