##  Trash jump plugin

This plugin allows to jump to first valid address inside a string full of garbage. By defauly, IDA PRO doesn't allow you to enter an invalid address to jump to.

For example, when you use `Ctrl+C` to copy current line data in OllyDBG 1.10/2.x you will have copied the string like shown below:

```
539554FB                                      E8 F00F0000      CALL Qt5Gui.539564F0
```

Cropping the address from the string beginning takes some time (your time) and this plugin will save this time for you.

Right after you copied the current line from Olly, just press ```G``` in IDA to run this plugin and do `Ctrl+V` and then `<Return>`.

The plugin will look for address strings using the following pattern `\b(0x)?([0-9a-f]+)\b` and will take the first `valid` address and navigate IDA there.

### FAQ

* If the shortcut isn't work then just assign it using IDA's 'Options->Shortcuts' view.


### Installation

Just copy `trash_jump.py` to your IDA PRO plugins directory, like ```%IDA_HOME%\plugins```.
