##  Trash jump plugin

This plugin allows to jump at specific address inside a string with trash inside.

For example when you made Ctrl+C in OllyDBG 1.10 you have string similar with

```
539554FB                                      E8 F00F0000      CALL Qt5Gui.539564F0
```

Then you just press ```G``` in IDA to run this plugin and paste this string with trash and press 'Return'.

The plugin looks for sub-strings using pattern ```[0-9a-f]+``` and if the address is valid - do jump there.

### FAQ

* If the shortcut isn't work - assign it using IDA's 'Options->Shortcuts' view.


### Installation

Just copy trash_jump.py to your IDA PRO plugins directory, like ```%IDA_HOME%\plugins```.