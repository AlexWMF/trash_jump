# -*- coding: utf-8 -*
__author__ = 'AlexWMF'


"""
    The MIT License (MIT)

    Copyright (c) 2015 AlexWMF
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
"""

import idaapi
import re
import traceback
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtCore import Qt


class UiCallable(object):
    def __init__(self, fn_or_fnlist):
        self.__fn = fn_or_fnlist

    def __call__(self):
        if isinstance(self.__fn, list):
            for item in self.__fn:
                item()
        else:
            self.__fn()
        return False


class TrashJumpDialog(QtWidgets.QDialog):
    def __init__(self, custom_base, parent=None, *args, **kwargs):
        super(TrashJumpDialog, self).__init__(parent, *args, **kwargs)
        self.cbb_addr = None
        self.le_custom_base = None
        self.lbl_diff = None
        self.custom_base = custom_base

        self.setUpUI()

    def setUpUI(self):
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setWindowTitle('Trash Jump')

        vlay = QtWidgets.QVBoxLayout(self)
        flay = QtWidgets.QFormLayout()

        lbl = QtWidgets.QLabel('TrashJump Address')
        flay.setWidget(0, QtWidgets.QFormLayout.LabelRole, lbl)

        self.cbb_addr = QtWidgets.QComboBox(self)
        self.cbb_addr.setEditable(True)
        flay.setWidget(0, QtWidgets.QFormLayout.FieldRole, self.cbb_addr)

        lbl = QtWidgets.QLabel('Custom base:', self)
        flay.setWidget(1, QtWidgets.QFormLayout.LabelRole, lbl)

        hlay = QtWidgets.QHBoxLayout()

        self.le_custom_base = QtWidgets.QLineEdit(self)
        self.le_custom_base.setMinimumSize(QtCore.QSize(161, 0))
        self.le_custom_base.setMaximumSize(QtCore.QSize(161, 16777215))

        self.le_custom_base.setText('0' if self.custom_base is None else '%x' % self.custom_base)
        self.le_custom_base.textChanged.connect(self.custom_base_changed)

        hlay.addWidget(self.le_custom_base)

        lbl = QtWidgets.QLabel('diff:', self)
        hlay.addWidget(lbl)

        self.lbl_diff = QtWidgets.QLabel(self)
        self.lbl_diff.setTextInteractionFlags(Qt.TextSelectableByMouse)
        hlay.addWidget(self.lbl_diff)

        hlay.setStretch(2, 1)
        flay.setLayout(1, QtWidgets.QFormLayout.FieldRole, hlay)
        vlay.addLayout(flay)

        bb = QtWidgets.QDialogButtonBox(self)
        bb.setOrientation(Qt.Horizontal)
        bb.setCenterButtons(True)
        bb.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)

        vlay.addWidget(bb)

        self.resize(421, 102)
        self.custom_base_changed(self.le_custom_base.text())

    def accept(self):
        try:
            self.custom_base = int(self.le_custom_base.text(), 16)
            super(TrashJumpDialog, self).accept()
        except:
            pass

    def custom_base_changed(self, s):
        try:
            self.custom_base = int(self.le_custom_base.text(), 16)
            self.lbl_diff.setText('%x' % (idaapi.get_imagebase() - self.custom_base))
        except:
            self.lbl_diff.setText('<invalid>')


class trash_jump_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = ""

    help = ""
    wanted_name = "Trash Jump"
    wanted_hotkey = "G"
    _RE_ADDR = re.compile(r'\b(0x)?([0-9a-f]+)\b', re.I | re.U | re.M)

    NET_NODE = '$ trash_jump'

    def init(self):
        return idaapi.PLUGIN_OK

    @classmethod
    def parse(cls, s):
        rv = list()
        for _, addr in cls._RE_ADDR.findall(s.strip()):
            if not addr:
                continue
            try:
                if '0x' not in addr.lower():
                    addr = '0x' + addr
                rv.append(long(addr, 16))
            except:
                print 'err: %s' % traceback.format_exc()
        return rv

    def run(self, arg):
        cfn = UiCallable(self._run)
        idaapi.execute_ui_requests((cfn,))

    def get_config(self):
        n = idaapi.netnode()
        n.create(self.NET_NODE)

        return {
            'custom_base': n.altval(0)
        }

    def save_config(self, cfg):
        n = idaapi.netnode()
        n.create(self.NET_NODE)

        n.altset(0, cfg['custom_base'] if cfg['custom_base'] else 0)

    def _run(self):
        try:
            askd = TrashJumpDialog(self.get_config()['custom_base'])
            if askd.exec_() != askd.Accepted:
                return

            s = askd.cbb_addr.currentText().encode('ascii').strip()
            diff = 0
            if askd.custom_base:
                diff = idaapi.get_imagebase() - askd.custom_base
                self.save_config({'custom_base': askd.custom_base})

            eas = self.parse(s)
            for ea in eas:
                ea += diff
                if idaapi.isEnabled(ea) and idaapi.jumpto(ea, idaapi.UIJMP_ACTIVATE | idaapi.UIJMP_IDAVIEW):
                    return

            ea = idaapi.get_name_ea(idaapi.BADADDR, s)
            if idaapi.BADADDR != ea:
                if idaapi.isEnabled(ea) and idaapi.jumpto(ea, idaapi.UIJMP_ACTIVATE | idaapi.UIJMP_IDAVIEW):
                    return

            # last try without custom base
            for ea in eas:
                if idaapi.isEnabled(ea) and idaapi.jumpto(ea, idaapi.UIJMP_ACTIVATE | idaapi.UIJMP_IDAVIEW):
                    return

            idaapi.msg('TrashJump: address not found. Parsed: %r\n' % [hex(ea) for ea in eas])
        except:
            idaapi.msg('TrashJump: address not found\nerror: %s\n' % traceback.format_exc())

    def term(self):
        pass


def PLUGIN_ENTRY():
    return trash_jump_plugin_t()

# if __name__ == '__main__':
#     import unittest
#     class SimpleTest(unittest.TestCase):
#         def test_1(self):
#             s = '50A66F10 ; Exported entry 2967. ?detac'
#             self.assertEqual(trash_jump_plugin_t.parse(s)[0], 0x50A66F10)
#     unittest.main()
