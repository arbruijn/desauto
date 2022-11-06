Automate various Descent source ports on Linux

Very experimental tool.

Currently fires a Homing missile on start of D1 level 1 and logs its
position.

### How to install
pip install frida git+https://github.com/arbruijn/pydwarfdb

build source port with debug info

### How to run
./desauto.py source-port-binary

It tries to figure out the source port type from the binary path/name,
supported: retro, rebirth and chocolate.
