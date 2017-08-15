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


class trash_jump_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = ""

    help = ""
    wanted_name = "Trash Jump"
    wanted_hotkey = "G"
    _RE_ADDR = re.compile(r'\b(0x)?([0-9a-f]+)\b', re.I | re.U | re.M)

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
                pass
                print 'err: %s' % traceback.format_exc()
        return rv

    def run(self, arg):
        cfn = UiCallable(self._run)
        idaapi.execute_ui_requests((cfn,))

    def _run(self):
        try:
            s = idaapi.askstr(0, None, 'TrashJump Address')
            if not s:
                return
            eas = self.parse(s)
            for ea in eas:
                if idaapi.jumpto(ea, idaapi.UIJMP_ACTIVATE | idaapi.UIJMP_IDAVIEW):
                    return

            ea = idaapi.get_name_ea(idaapi.BADADDR, s.strip())
            if idaapi.BADADDR != ea:
                if idaapi.jumpto(ea, idaapi.UIJMP_ACTIVATE | idaapi.UIJMP_IDAVIEW):
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
