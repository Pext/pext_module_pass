#!/usr/bin/env python3

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

import re
import os
from os.path import expanduser
from subprocess import check_output
from shlex import quote

import pexpect

from pext_base import ModuleBase
from pext_helpers import Action, SelectionType

import pyinotify


class Module(ModuleBase):
    def init(self, settings, q):
        self.binary = "pass" if ('binary' not in settings) else settings['binary']

        self.q = q

        self.ANSIEscapeRegex = re.compile('(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
        self.passwordEntries = {}

        self._getCommands()
        self._getEntries()

        self._initInotify(q)

    def _initInotify(self, q):
        # Initialize the EventHandler and make it watch the password store
        eventHandler = EventHandler(q, self)
        watchManager = pyinotify.WatchManager()
        self.notifier = pyinotify.ThreadedNotifier(watchManager, eventHandler)
        watchedEvents = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_MOVED_FROM | pyinotify.IN_MOVED_TO | pyinotify.IN_OPEN
        watchManager.add_watch(self._getDataLocation(), watchedEvents, rec=True, auto_add=True)
        self.notifier.daemon = True
        self.notifier.start()

    def _getDataLocation(self):
        return expanduser("~") + "/.password-store/"

    def _getSupportedCommands(self):
        return ["show", "init", "insert", "edit", "generate", "rm", "mv", "cp"]

    def _getCommands(self):
        # We will crash here if pass is not installed.
        # TODO: Find a nice way to notify the user they need to install pass
        commandText = check_output([self.binary, "--help"])

        for line in commandText.splitlines():
            strippedLine = line.lstrip().decode("utf-8")
            if strippedLine[:4] == "pass":
                command = strippedLine[5:]
                for supportedCommand in self._getSupportedCommands():
                    if command.startswith(supportedCommand):
                        self.q.put([Action.addCommand, command])

    def _getEntries(self):
        passDir = self._getDataLocation()

        unsortedPasswords = []
        for root, dirs, files in os.walk(passDir):
            for name in files:
                if name[-4:] == ".gpg":
                    unsortedPasswords.append(os.path.join(root, name))

        for password in sorted(unsortedPasswords, key=lambda name: os.path.getatime(os.path.join(root, name)), reverse=True):
            entry = password[len(passDir):-4]
            self.q.put([Action.addEntry, entry])

    def _runCommand(self, command, printOnSuccess=False, hideErrors=False, prefillInput=''):
        # Ensure this is a valid command
        if command[0] not in self._getSupportedCommands():
            return None

        # If we edit a password, make sure to get the original input first so we can show the user
        if command[0] == "edit" and len(command) == 2:
            prefillData = self._runCommand(["show", command[1]], hideErrors=True)

            if self.proc['result'] == pexpect.TIMEOUT:
                return None

            if prefillData is None:
                prefillData = ''

            return self._runCommand(["insert", "-fm", command[1]], printOnSuccess=True, prefillInput=prefillData.rstrip())

        sanitizedCommandList = [quote(commandPart) for commandPart in command]
        command = " ".join(sanitizedCommandList)

        proc = pexpect.spawn('/bin/sh', ['-c', self.binary + " " + command + (" 2>/dev/null" if hideErrors else "")])
        return self._processProcOutput(proc, command, printOnSuccess, hideErrors, prefillInput)

    def _processProcOutput(self, proc, command, printOnSuccess=False, hideErrors=False, prefillInput=''):
        possibleResults = [pexpect.EOF, pexpect.TIMEOUT, "[Y/n]", "[y/N]", "Enter password ", "Retype password ", " and press Ctrl+D when finished:"]
        result = proc.expect_exact(possibleResults, timeout=3)
        if result == 0:
            self.proc = {'result': possibleResults[result]}
            exitCode = proc.sendline("echo $?")
        elif result == 1:
            self.proc = {'result': possibleResults[result]}
            self.q.put([Action.addError, "Timeout error while running '{}'".format(command)])
            if proc.before:
                self.q.put([Action.addError, "Command output: {}".format(self.ANSIEscapeRegex.sub('', proc.before.decode("utf-8")))])

            return None
        elif result == 2 or result == 3:
            proc.setecho(False)
            question = proc.before.decode("utf-8")

            if (result == 2):
                self.proc = {'proc': proc,
                             'command': command,
                             'type': Action.askQuestionDefaultYes,
                             'printOnSuccess': printOnSuccess,
                             'hideErrors': hideErrors,
                             'prefillInput': prefillInput,
                             'result': possibleResults[result]}
                self.q.put([Action.askQuestionDefaultYes, question])
            else:
                self.proc = {'proc': proc,
                             'command': command,
                             'type': Action.askQuestionDefaultNo,
                             'printOnSuccess': printOnSuccess,
                             'hideErrors': hideErrors,
                             'prefillInput': prefillInput,
                             'result': possibleResults[result]}
                self.q.put([Action.askQuestionDefaultNo, question])

            return None
        elif result == 4 or result == 5:
            printOnSuccess = False
            proc.setecho(False)
            self.proc = {'proc': proc,
                         'command': command,
                         'type': Action.askInputPassword,
                         'printOnSuccess': printOnSuccess,
                         'hideErrors': hideErrors,
                         'prefillInput': prefillInput,
                         'result': possibleResults[result]}
            self.q.put([Action.askInputPassword, proc.after.decode("utf-8")])

            return None
        elif result == 6:
            self.proc = {'proc': proc,
                         'command': command,
                         'type': Action.askInputMultiLine,
                         'printOnSuccess': printOnSuccess,
                         'hideErrors': hideErrors,
                         'prefillInput': prefillInput,
                         'result': possibleResults[result]}
            self.q.put([Action.askInputMultiLine, proc.before.decode("utf-8").lstrip(), prefillInput])

            proc.setecho(False)

            return None

        proc.close()
        exitCode = proc.exitstatus

        message = self.ANSIEscapeRegex.sub('', proc.before.decode("utf-8")) if proc.before else ""

        self.q.put([Action.setFilter, ""])

        if exitCode == 0:
            if printOnSuccess and message:
                self.q.put([Action.addMessage, message])

            return message
        else:
            self.q.put([Action.addError, message if message else "Error code {} running '{}'. More info may be logged to the console".format(str(exitCode), command)])

            return None

    def processResponse(self, response):
        if self.proc['type'] == Action.askQuestionDefaultYes or self.proc['type'] == Action.askQuestionDefaultNo:
            self.proc['proc'].waitnoecho()
            self.proc['proc'].sendline('y' if response else 'n')
            self.proc['proc'].setecho(True)
        elif self.proc['type'] == Action.askInput or self.proc['type'] == Action.askInputPassword:
            self.proc['proc'].waitnoecho()
            if response is None:
                self.proc['proc'].close()
            else:
                self.proc['proc'].sendline(response)
                self.proc['proc'].setecho(True)
        elif self.proc['type'] == Action.askInputMultiLine:
            self.proc['proc'].waitnoecho()
            if response is None:
                # At this point, pass won't let us exit out safely, so we
                # write the prefilled data
                for line in self.proc['prefillInput'].splitlines():
                    self.proc['proc'].sendline(line)
            else:
                for line in response.splitlines():
                    self.proc['proc'].sendline(line)

            self.proc['proc'].sendcontrol("d")
            self.proc['proc'].setecho(True)

        self._processProcOutput(self.proc['proc'], self.proc['command'], printOnSuccess=self.proc['printOnSuccess'], hideErrors=self.proc['hideErrors'], prefillInput=self.proc['prefillInput'])


    def stop(self):
        self.notifier.stop()

    def selectionMade(self, selection):
        if len(selection) == 0:
            # We're at the main menu
            self.passwordEntries = {}
            self.q.put([Action.setHeader])
            self.q.put([Action.replaceCommandList, []])
            self.q.put([Action.replaceEntryList, []])
            self._getCommands()
            self._getEntries()
        elif len(selection) == 1:
            if selection[0]["type"] == SelectionType.command:
                parts = selection[0]["value"].split(" ")
                self._runCommand(parts)
                self.q.put([Action.setSelection, []])
            elif selection[0]["type"] == SelectionType.entry:
                results = self._runCommand(["show", selection[0]["value"]], hideErrors=True)
                if results is None:
                    self.q.put([Action.setSelection, []])
                    return

                self.q.put([Action.setHeader, selection[0]["value"]])
                self.q.put([Action.replaceEntryList, []])
                self.q.put([Action.replaceCommandList, []])

                for line in results.rstrip().splitlines():
                    if len(self.passwordEntries) == 0:
                        self.passwordEntries["********"] = line
                        self.q.put([Action.addEntry, "********"])
                    else:
                        self.passwordEntries[line] = line
                        self.q.put([Action.addEntry, line])
            else:
                self.q.put([Action.criticalError, "Unexpected selectionMade value: {}".format(selection)])
        elif len(selection) == 2:
            # We're selecting a password
            if selection[1]["value"] == "********":
                self.q.put([Action.copyToClipboard, self.passwordEntries["********"]])
            else:
                # Get the final part to prepare for copying. For example, if
                # the entry is named URL: https://example.org/", only copy
                # "https://example.org/" to the clipboard
                copyStringParts = self.passwordEntries[selection[1]["value"]].split(": ", 1)

                copyString = copyStringParts[1] if len(copyStringParts) > 1 else copyStringParts[0]
                self.q.put([Action.copyToClipboard, copyString])

            self.q.put([Action.close])
        else:
            self.q.put([Action.criticalError, "Unexpected selectionMade value: {}".format(selection)])

class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, q, store):
        self.q = q
        self.store = store

    def process_IN_CREATE(self, event):
        if event.dir or len(self.store.passwordEntries) > 0:
            return

        entryName = event.pathname[len(self.store._getDataLocation()):-4]

        self.q.put([Action.prependEntry, entryName])

    def process_IN_DELETE(self, event):
        if event.dir or len(self.store.passwordEntries) > 0:
            return

        entryName = event.pathname[len(self.store._getDataLocation()):-4]

        self.q.put([Action.removeEntry, entryName])

    def process_IN_MOVED_FROM(self, event):
        self.process_IN_DELETE(event)

    def process_IN_MOVED_TO(self, event):
        self.process_IN_CREATE(event)

    def process_IN_OPEN(self, event):
        if event.dir or len(self.store.passwordEntries) > 0:
            return

        entryName = event.pathname[len(self.store._getDataLocation()):-4]

        self.q.put([Action.prependEntry, entryName])
        self.q.put([Action.removeEntry, entryName])
