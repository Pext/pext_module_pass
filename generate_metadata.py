#!/usr/bin/env python3

# Copyright (C) 2016 - 2018 Sylvia van Os <sylvia@hackerchick.me>
#
# Pext pass module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import gettext
import json
import os

languages = [dirname for dirname in os.listdir(os.path.join('.', 'locale')) if os.path.isdir(os.path.join('.', 'locale', dirname))] + [None]

for language in languages:
    if not language:
        lang = gettext.NullTranslations()
    else:
        try:
            lang = gettext.translation('pext_module_pass', localedir=os.path.join('.', 'locale'), languages=[language])
        except FileNotFoundError:
            lang = gettext.NullTranslations()
            print("No {} metadata translation available for pext_module_pass".format(language))
            continue

    lang.install()
    
    filename = 'metadata_{}.json'.format(language) if language else 'metadata.json'
    metadata_file = open(filename, 'w')
    json.dump({'id': 'pext.module.pass',
               'name': _('Password Store'),
               'developer': 'Sylvia van Os',
               'description': _('Allows Pext to do password management through pass'),
               'homepage': 'https://pext.io/',
               'license': 'GPL-3.0+',
               'git_urls': ['https://github.com/Pext/pext_module_pass'],
               'bugtracker': 'https://github.com/Pext/pext_module_pass',
               'bugtracker_type': 'github',
               'settings': [{
                             'name': 'directory',
                             'description': _('Password Store directory'),
                             'default': '~/.password-store/'
                            },
                            {
                              'name': 'use_git',
                              'description': _('Automatically pull and push changes to/from Git'),
                              'options': [_('Yes'), _('No')],
                              'default': _('Yes')
                            },
                            {
                              'name': 'ssh_password',
                              'description': _('Password of SSH key, if encrypted, for push/pull. Stored in plain text.'),
                              'default': ''
                            }],
               'platforms': ['Linux', 'Darwin']},
              metadata_file, indent=2, sort_keys=True)
