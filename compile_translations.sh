#!/bin/sh

pygettext2.6.py -d pext_module_pass -a -- *.py

for dir in locale/*/LC_MESSAGES; do
    msgmerge -U -N "$dir/pext_module_pass.po" pext_module_pass.pot
    msgfmt "$dir/pext_module_pass.po" -o "$dir/pext_module_pass.mo"
done

python3 generate_metadata.py

# Copy to names with country code
cp metadata_nl.json metadata_nl_NL.json
