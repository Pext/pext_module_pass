from .abstract_password_manager import AbstractPasswordManager

import platform
from os.path import expanduser, normcase

from babel.dates import format_datetime
from dulwich import client, porcelain
from dulwich.file import FileLocked
from dulwich.repo import Repo
from dulwich.contrib.paramiko_vendor import ParamikoSSHVendor
from paramiko import ssh_exception

import pypass

class PasswordManager(AbstractPasswordManager):
    def initialize(self) -> bool:
        if platform.system() == 'Darwin':
            # Explicitly add support for MacGPG2
            os.environ['PATH'] = os.environ['PATH'] + ':/usr/local/MacGPG2/bin'

        self.data_location = expanduser(normcase("~/.password-store/")) if ('directory' not in settings) else expanduser(normcase(settings['directory']))
        self.password_store = pypass.PasswordStore(self.data_location)

        if 'ssh_password' not in self.settings or not self.settings['ssh_password']:
            self.settings['ssh_password'] = None

        self.git_repo = self.data_location
        if (not os.path.isdir(os.path.join(self.data_location, ".git"))) or ('use_git' in self.settings and self.settings['use_git'] == _('No')):
            self.git_repo = None

        if not os.path.exists(os.path.join(self.data_location, ".gpg-id")):
            self._init()

        return True

    def update(self) -> bool:
        if not _git_pull():
            return False
        
        if not _git_push():
            return False

        return True

    def _get_data_location(self):
        return self.data_location

    def _git_pull(self) -> bool:
        try:
            if self.git_repo:
                with Repo(self.git_repo) as repo:
                    config = repo.get_config()
                    remote_url = config.get(("remote".encode(), "origin".encode()), "url".encode()).decode()
                    client.get_ssh_vendor = ParamikoSSHVendor
                    try:
                        porcelain.pull(repo, remote_url, password=self.settings['ssh_password'])
                    except (ssh_exception.SSHException, OSError) as e:
                        self.q.put([Action.add_error, _("Failed to pull from Git: {}").format(str(e))])

            return
        except FileLocked:
            return False

        return True

    def _git_push(self) -> bool:
        try:
            if self.git_repo:
                with Repo(self.git_repo) as repo:
                    config = repo.get_config()
                    remote_url = config.get(("remote".encode(), "origin".encode()), "url".encode()).decode()
                    client.get_ssh_vendor = ParamikoSSHVendor
                    try:
                        porcelain.push(repo, remote_url, 'master', password=self.settings['ssh_password'])
                    except (ssh_exception.SSHException, OSError) as e:
                        self.q.put([Action.add_error, _("Failed to push to Git: {}").format(str(e))])

            return
        except FileLocked:
            return False

        return True

    def get_passwords(self) -> List[str]:
        self.retrieve_updates()

        passwords = []

        for password in sorted(self.password_store.get_passwords_list(), key=lambda name: os.path.getatime("{}.gpg".format(name)), reverse=True):
            entry = password[len(self._get_data_location()):]

            passwords.append(entry)

        return passwords

    def get_breached_passwords(self) -> bool:
        # TODO
        pass

    def get_password_string(self, str: name) -> str:
        data = self.password_store.get_decrypted_password(name)
        return data[0] if len(data) > 0 else ""

    def get_password_metadata(self, str: name) -> List[Dict[str, str]]:
        metadata = []

        data = self.password_store.get_decrypted_password(name)
        for part in data[1:]:
            # OTP is in another function
            if part.startswith('otpauth://'):
                continue

            metadata_parts = self.passwordEntries[selection[1]["value"]].split(": ", 1)

            key = ""
            if len(metadata_parts) > 1:
                key = metadata_parts[0]
                value = metadata_parts[1]
            else:
                value = metadata_parts[0]
            metadata.append([key, value])

        return metadata

    def get_password_otp(self, str: name) -> List[str]:
        otps = []

        data = self.password_store.get_decrypted_password(name)
        for part in data[1:]:
            if part.startswith('otpauth://'):
                otps.append(part)

        return otps 

    def get_password_description(self, str: name) -> str:
        entry_path = os.path.join(self._get_data_location(), "{}.gpg".format(name))
        last_opened = datetime.fromtimestamp(os.path.getatime(entry_path))
        last_modified = datetime.fromtimestamp(os.path.getmtime(entry_path))

        return _("<b>{}</b><b>Last opened</b><br/>{}<br/><br/><b>Last modified</b><br/>{}").format(html.escape(name), format_datetime((last_opened).replace(microsecond=0), locale=self.settings['_locale']), format_datetime((last_modified).replace(microsecond=0), locale=self.settings['_locale']))])

    def set_password_string(self, str: name, str: value) -> bool:
        current_data = self.password_store.get_decrypted_password(name).splitlines()
        current_data[0] = value
        return self._save_password(name, '\n'.join(current_data))

    def set_password_metadata(self, str: name, List[Dict[str, str]]: value) -> bool:
        new_data = []

        current_data = self.password_store.get_decrypted_password(name).splitlines()

        # Password
        new_data.append(current_data[0])

        # Metadata
        for part in value:
            new_data.append(part)

        # OTP
        for current_part in current_data[1:]:
            if current_part.startswith('otpauth://'):
                new_data.append(current_part)

        return self._save_password(name, '\n'.join(new_data))

    def set_password_otp(self, str: name, List[Dict[str, str]]: value) -> bool:
        new_data = []

        current_data = self.password_store.get_decrypted_password(name).splitlines()

        # Password
        new_data.append(current_data[0])

        # Metadata
        for current_part in current_data[1:]:
            if not current_part.startswith('otpauth://'):
                new_data.append(current_part)

        # OTP
        for part in value:
            new_data.append(part)

        return self._save_password(name, '\n'.join(new_data))
