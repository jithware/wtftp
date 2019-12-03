# WTFTP Plugins

## Wireshark
The [wireshark/wtftp](./wireshark/wtftp) directory contains the source to build the wtftp wireshark dissector. It is not intended to be built in this project. 

Get the wireshark source:
```shell
git clone https://code.wireshark.org/review/wireshark
cd wireshark
git checkout master-2.4
```

Copy or link this directory to the wireshark plugins directory and add it to the CMakeListsCustom.txt file:
```cmake
set(CUSTOM_PLUGIN_SRC_DIR
	plugins/wtftp
)
```

Build wireshark 
```shell
cd ..
mkdir wireshark.build
cd wireshark.build
cmake ../wireshark
make
```

When building is complete verify in the output the plugin was built
```shell
Built target wtftp
```

Run wireshark
```shell
./run/wireshark
```