# WTFTP Plugins

### Wireshark
The wtftp directory contains the source to build the wtftp wireshark dissector. It is not intended to be built in this project. Copy this directory to the wireshark plugins directory and add it to the CMakeListsCustom.txt file:

```cmake
set(CUSTOM_PLUGIN_SRC_DIR
	plugins/wtftp
)
```

Then follow the wireshark cmake build instructions.