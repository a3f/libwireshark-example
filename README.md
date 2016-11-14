#### Sample project showcasing stand-alone use of libwireshark.

Tested working with Wireshark 2.3.0 on macOS Sierra.

#### Usage

    mkdir build && cd build
    cmake ..
    make
    ./libwireshark-example -f ../1.pcap

Code is released under same terms as [tshark](https://github.com/boundary/wireshark/blob/master/tshark.c), which it's based on (GNU GPL2.0+). It contains [code by Sun Wang](https://github.com/sunwxg/decode_by_libwireshark), originally under the MIT license.
