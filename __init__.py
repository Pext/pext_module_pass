#!/usr/bin/env python3

# Copyright (C) 2016 - 2019 Sylvia van Os <sylvia@hackerchick.me>
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
import html
import json
import os
import shutil
import threading
from datetime import date, datetime
from time import sleep

import pyotp
import pyscreenshot
import zbar

from pext_base import ModuleBase
from pext_helpers import Action, SelectionType


class Module(ModuleBase):
    def init(self, settings, q):
        try:
            lang = gettext.translation('pext_module_pass', localedir=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'locale'), languages=[settings['_locale']])
        except FileNotFoundError:
            lang = gettext.NullTranslations()
            print("No {} translation available for pext_module_pass".format(settings['_locale']))

        lang.install()

        self.result_display_thread = None
        self.result_display_active = True

        self.q = q
        self.settings = settings

        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'breaches.json')) as breaches_json:
            self.breaches = json.load(breaches_json)

        if self.settings['_api_version'] < [0, 11, 1]:
            self.q.put([Action.critical_error, _("This module requires at least API version 0.11.1, you are using {}. Please update Pext.").format(".".join([str(i) for i in self.settings['_api_version']]))])
            return

        from implementations.password_store import PasswordManager
        self.password_manager = PasswordManager()

        self.q.put([Action.set_base_context, [_("Create"), _("Generate")]])

    def process_response(self, response, identifier):
        # User cancellation
        if response is None:
            return

        data = identifier.split()
        if data[0] == "view_breaches":
            if response is True:
                self.q.put([Action.set_selection, [{"type": SelectionType.none, "context_option": _("View data breaches"), "value": ""}]])
        elif data[0] == "add_otp":
            if len(data) == 1:
                if response is not None:
                    self._add_otp(name=response)
                else:
                    self._add_otp()
            else:
                if response is not None:
                    if data[-1] in ["TOTP", "HOTP"]:
                        self._add_otp(name=" ".join(data[1:-1]), otp_type=data[-1], secret=response)
                    else:
                        self._add_otp(name=" ".join(data[1:]), otp_type=response)
                else:
                    if data[-1] in ["TOTP", "HOTP"]:
                        self._add_otp(name=" ".join(data[1:-1], otp_type=data[-1]))
                    else:
                        self._add_otp(name=" ".join(data[1:]))
        elif data[0] == "copy":
            if len(data) == 1:
                if response is not None:
                    self._copy(name=response)
                else:
                    self._copy()
            else:
                if response is not None:
                    self._copy(name=" ".join(data[1:]), copy_name=response)
                else:
                    self._copy(name=" ".join(data[1:]))
        elif data[0] == "edit_password":
            if len(data) == 1:
                if response is not None:
                    self._edit_password(name=response)
                else:
                    self._edit_password()
            else:
                if response is not None:
                    self._edit_password(name=" ".join(data[1:]), value=response)
                else:
                    self._edit_password(name=" ".join(data[1:]))
        elif data[0] == "edit_other_fields":
            if len(data) == 1:
                if response is not None:
                    self._edit_other_fields(name=response)
                else:
                    self._edit_other_fields()
            else:
                if response is not None:
                    self._edit_other_fields(name=" ".join(data[1:]), value=response)
                else:
                    self._edit_other_fields(name=" ".join(data[1:]))
        elif data[0] == "generate":
            if len(data) == 1:
                if response is not None:
                    self._generate(name=response)
                else:
                    self._generate()
            else:
                if response is not None:
                    self._generate(name=" ".join(data[1:]), length=response if response else 15)
                else:
                    self._generate(name=" ".join(data[1:]))
        elif data[0] == "init":
            if response is not None:
                self._init(gpg_id=response)
            else:
                self._init()
        elif data[0] == "insert":
            if len(data) == 1:
                if response is not None:
                    self._insert(name=response)
                else:
                    self._insert()
            else:
                if response is not None:
                    self._insert(name=" ".join(data[1:]), value=response)
                else:
                    self._insert(name=" ".join(data[1:]))
        elif data[0] == "remove":
            if len(data) == 1:
                if response is not None:
                    self._remove(name=response)
                else:
                    self._remove()
            else:
                if response is not None:
                    self._remove(name=" ".join(data[1:]), confirmed=response)
                else:
                    self._remove(name=" ".join(data[1:]))
        elif data[0] == "rename":
            if len(data) == 1:
                if response is not None:
                    self._rename(name=response)
                else:
                    self._rename()
            else:
                if response is not None:
                    self._rename(name=" ".join(data[1:]), new_name=response)
                else:
                    self._rename(name=" ".join(data[1:]))
        else:
            self.q.put([Action.critical_error, _("Unknown request received: {}").format(" ".join(data))])

    def _save_password(self, name, value):
        if not value.endswith('\n'):
            value = "{}\n".format(value)

        self.password_store.insert_password(name, value)

        if self.git_repo:
            porcelain.add(self.git_repo, os.path.join(self._get_data_location(), "{}.gpg".format(name)))
            porcelain.commit(self.git_repo, message="Created/Modified {} with Pext".format(name))
            self._git_push()

    def _append_password(self, name, value):
        current_data = self.password_store.get_decrypted_password(name)

        if not current_data.endswith('\n'):
            current_data = "{}\n".format(current_data)

        if not value.endswith('\n'):
            value = "{}\n".format(value)

        self.password_store.insert_password(name, "{}{}".format(current_data, value))

        if self.git_repo:
            porcelain.add(self.git_repo, os.path.join(self._get_data_location(), "{}.gpg".format(name)))
            porcelain.commit(self.git_repo, message="Appended to {} with Pext".format(name))
            self._git_push()

    def _add_otp(self, name=None, otp_type=None, secret=None):
        if not name:
            self.q.put([Action.ask_input, _("What password should OTP be added to?"), "", "add_otp"])
        elif not otp_type:
            screenshot = pyscreenshot.grab(childprocess=False).convert('L')
            qr_codes = zbar.Scanner().scan(screenshot)
            autodetected = 0
            for qr_code in qr_codes:
                qr_data = qr_code.data.decode()
                try:
                    pyotp.parse_uri(qr_data)
                except ValueError:
                    continue

                autodetected += 1
                self._append_password(name, qr_data)

            if autodetected == 0:
                self.q.put([Action.add_error, _("No valid OTP QR codes detected on your screen. Configuring manually…")])
                self.q.put([Action.ask_choice, _("Which OTP type should be used?"), ["TOTP", "HOTP"], "add_otp {}".format(name)])
            else:
                self.q.put([Action.add_message, _("Detected and added {} valid OTP QR code(s) on your screen.").format(str(autodetected))])
                return
        elif not secret:
            self.q.put([Action.ask_input, _("What is the OTP secret?"), "", "add_otp {} {}".format(name, otp_type)])
        else:
            if otp_type == "TOTP":
                otp_uri = pyotp.TOTP(secret).provisioning_uri()
            elif otp_type == "HOTP":
                otp_uri = pyotp.HOTP(secret).provisioning_uri()
            else:
                return

            self._append_password(name, otp_uri)

    def _copy(self, name=None, copy_name=None):
        if not name:
            self.q.put([Action.ask_input, _("Which password do you want to copy?"), "", "copy"])
        elif not copy_name:
            self.q.put([Action.ask_input, _("What should the copy of {} be named?").format(name), name, "copy {}".format(name)])
        else:
            try:
                original_file_path = os.path.join(self._get_data_location(), "{}.gpg".format(name))
                copy_file_path = os.path.join(self._get_data_location(), "{}.gpg".format(copy_name))
                shutil.copyfile(original_file_path, copy_file_path)

                if self.git_repo:
                    porcelain.add(self.git_repo, [copy_file_path])
                    porcelain.commit(self.git_repo, message="Copied {} to {} with Pext".format(name, copy_name))
                    self._git_push()
            except shutil.SameFileError:
                self.q.put([Action.ask_input, _("What should the copy of {} be named?").format(name), name, "copy {}".format(name)])
                return

            self.q.put([Action.set_selection, []])

    def _edit_password(self, name=None, value=None):
        if not name:
            self.q.put([Action.ask_input, _("What password do you want to change?"), "", "edit"])
        else:
            if not value:
                self.q.put([Action.ask_input_password, _("What should the value of {} be?").format(name), "", "edit_password {}".format(name)])
            else:
                current_data = self.password_store.get_decrypted_password(name).splitlines()
                current_data[0] = value
                self._save_password(name, '\n'.join(current_data))
                self.q.put([Action.set_selection, []])

    def _edit_other_fields(self, name=None, value=None):
        if not name:
            self.q.put([Action.ask_input, _("What password do you want to change fields of?"), "", "edit"])
        else:
            current_data = self.password_store.get_decrypted_password(name).splitlines()
            fields = '\n'.join(current_data[1:]) if len(current_data) > 1 else ''
            if not value:
                self.q.put([Action.ask_input_multi_line, _("What should the value of the fields of {} be?").format(name), fields, "edit_other_fields {}".format(name)])
            else:
                data = "{}\n{}".format(current_data[0], value)
                self._save_password(name, data)
                self.q.put([Action.set_selection, []])

    def _generate(self, name=None, length=None):
        if not name:
            self.q.put([Action.ask_input, _("What name do you want to generate a random password for?"), "", 'generate'])
        elif not length:
            self.q.put([Action.ask_input, _("How many characters should the password be?"), "15", "generate {}".format(name)])
        else:
            password = self.password_store.generate_password(name, length=int(length))
            self._insert(name=name, value=password)

    def _init(self, gpg_id=None):
        if not gpg_id:
            self.q.put([Action.ask_input, _("Please provide a GPG key ID to initialize this directory with."), "", "init"])
        else:
            self.password_store.init(gpg_id, self._get_data_location)
            self.q.put([Action.set_selection, []])

    def _insert(self, name=None, value=None):
        if not name:
            self.q.put([Action.ask_input, _("What is the name of the password?"), "", 'insert'])
        elif not value:
            self.q.put([Action.ask_input_password, _("What should the value of {} be?").format(name), "", "insert {}".format(name)])
        else:
            self._save_password(name, value)
            self.q.put([Action.set_selection, []])

    def _remove(self, name=None, confirmed=None):
        if not name:
            self.q.put([Action.ask_input, _("What password do you want to remove?"), "", "remove"])
        elif confirmed is None:
            self.q.put([Action.ask_question, _("Are you sure you want to remove {}?").format(name), "remove {}".format(name)])
        elif not confirmed:
            return
        else:
            file_path = os.path.join(self._get_data_location(), "{}.gpg".format(name))
            os.remove(file_path)

            if self.git_repo:
                porcelain.add(self.git_repo, [file_path])
                porcelain.commit(self.git_repo, message="Removed {} with Pext".format(name))
                self._git_push()

            self.q.put([Action.set_selection, []])

    def _rename(self, name=None, new_name=None):
        if not name:
            self.q.put([Action.ask_input, _("What password do you want to rename?"), "", "rename"])
        elif not new_name:
            self.q.put([Action.ask_input, _("What should the new name of {} be?").format(name), name, "rename {}".format(name)])
        else:
            old_file_path = os.path.join(self._get_data_location(), "{}.gpg".format(name))
            new_file_path = os.path.join(self._get_data_location(), "{}.gpg".format(new_name))
            os.rename(old_file_path, new_file_path)

            if self.git_repo:
                porcelain.add(self.git_repo, [old_file_path, new_file_path])
                porcelain.commit(self.git_repo, message="Renamed {} to {} with Pext".format(name, new_name))
                self._git_push()

            self.q.put([Action.set_selection, []])

    def _display_results(self, results):
        while self.result_display_active:
            result_lines = results.rstrip().splitlines()
            self.passwordEntries = {}
            # Parse OTP
            for number, line in enumerate(result_lines):
                try:
                    otp = pyotp.parse_uri(line)
                except ValueError:
                    continue

                if isinstance(otp, pyotp.TOTP):
                    otp_code = otp.now()
                else:
                    otp_code = otp.generate_otp()

                otp_description = "{} - {}".format(otp.issuer, otp.name) if otp.issuer else otp.name
                result_lines[number] = "OTP ({}): {}".format(otp_description, otp_code)

            # If only a password and no other fields, select password immediately
            if len(result_lines) == 1:
                self.q.put([Action.copy_to_clipboard, result_lines[0]])
                self.q.put([Action.close])
                return

            for line in result_lines:
                if len(self.passwordEntries) == 0:
                    self.passwordEntries["********"] = line
                else:
                    self.passwordEntries[line] = line

            self.q.put([Action.replace_entry_list, ["********"] + result_lines[1:]])

            if self.result_display_active:
                sleep(1)

    def selection_made(self, selection):
        if len(selection) == 0:
            # We're at the main menu
            if self.result_display_thread:
                self.result_display_active = False
                self.result_display_thread.join()

            self.passwordEntries = {}
            self.q.put([Action.set_header])
            self.q.put([Action.replace_command_list, []])
            self.q.put([Action.replace_entry_list, []])
            self._get_entries()
        elif selection[-1]["type"] == SelectionType.none:
            if self.result_display_thread:
                self.result_display_active = False
                self.result_display_thread.join()

            # Global context menu option
            if selection[-1]["context_option"] == _("Create"):
                self._insert()
                self.q.put([Action.set_selection, []])
                return
            elif selection[-1]["context_option"] == _("Generate"):
                self._generate()
                self.q.put([Action.set_selection, []])
                return
            elif selection[-1]["context_option"] == _("View data breaches"):
                self.q.put([Action.set_header, _("Data breaches")])
                self.q.put([Action.replace_command_list, []])
                self.q.put([Action.replace_entry_list, []])
                if self._get_entries(breaches_only=True) == 0:
                    self.q.put([Action.add_error, _("No breached accounts found")])
                    self.q.put([Action.set_selection, []])
                return
            else:
                self.q.put([Action.critical_error, _("Unexpected selection_made value: {}").format(selection)])
        elif len(selection) == 2 and selection[-2]["type"] != SelectionType.none and selection[-2]["context_option"] != _("View data breaches"):
            # We're selecting a password
            if self.result_display_thread:
                self.result_display_active = False
                self.result_display_thread.join()

            if selection[1]["value"] == "********":
                self.q.put([Action.copy_to_clipboard, self.passwordEntries["********"]])
            else:
                # Get the final part to prepare for copying. For example, if
                # the entry is named URL: https://example.org/", only copy
                # "https://example.org/" to the clipboard
                copyStringParts = self.passwordEntries[selection[1]["value"]].split(": ", 1)

                copyString = copyStringParts[1] if len(copyStringParts) > 1 else copyStringParts[0]
                self.q.put([Action.copy_to_clipboard, copyString])

            self.passwordEntries = {}
            self.q.put([Action.close])
        else:
            if self.result_display_thread:
                self.result_display_active = False
                self.result_display_thread.join()

            if selection[-1]["type"] == SelectionType.entry:
                if selection[-1]["context_option"] == _("Edit password"):
                    self._edit_password(name=selection[-1]["value"])
                    self.q.put([Action.set_selection, []])
                    return
                elif selection[-1]["context_option"] == _("Edit other fields"):
                    self._edit_other_fields(name=selection[-1]["value"])
                    self.q.put([Action.set_selection, []])
                    return
                elif selection[-1]["context_option"] == _("Add OTP"):
                    self._add_otp(selection[-1]["value"])
                    self.q.put([Action.set_selection, []])
                    return
                elif selection[-1]["context_option"] == _("Copy"):
                    self._copy(name=selection[-1]["value"])
                    self.q.put([Action.set_selection, []])
                    return
                elif selection[-1]["context_option"] == _("Rename"):
                    self._rename(name=selection[-1]["value"])
                    self.q.put([Action.set_selection, []])
                    return
                elif selection[-1]["context_option"] == _("Remove"):
                    self._remove(selection[-1]["value"])
                    self.q.put([Action.set_selection, []])
                    return

                results = self.password_store.get_decrypted_password(selection[-1]["value"])
                if results is None:
                    self.q.put([Action.set_selection, []])
                    return

                self.q.put([Action.replace_entry_list, []])
                self.q.put([Action.replace_command_list, []])

                self.result_display_active = True
                self.result_display_thread = threading.Thread(target=self._display_results, args=(results,), daemon=True)
                self.result_display_thread.start()
            else:
                self.q.put([Action.critical_error, _("Unexpected selection_made value: {}").format(selection)])
