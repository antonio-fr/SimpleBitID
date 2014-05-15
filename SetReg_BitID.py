#! /usr/bin/env python

# Install BitId for Windows, "SetReg" of SimpleBitID
# Copyright (C) 2014  Antoine FERRON

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import os
import _winreg as wreg

key = wreg.OpenKey(wreg.HKEY_CLASSES_ROOT, "",0, wreg.KEY_WRITE)
keysub=wreg.CreateKey(key, "bitid")
wreg.SetValue(keysub, "", wreg.REG_SZ, "URL:BitID Protocol")
wreg.SetValueEx(keysub, "URL Protocol", 0, wreg.REG_SZ, "")
keysub2=wreg.CreateKey(keysub, "shell\\open\\command")
wreg.SetValue(keysub2, "", wreg.REG_SZ, "\""+os.getenv('ProgramFiles')+"\\SimpleBitID\\SimpleBitID.exe\" %1")