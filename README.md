#### Sample project showcasing stand-alone use of libwireshark.

Tested working with Wireshark `v2.2.3-0-g57531cdd46` on macOS Sierra. Keep in mind, that libwireshark is not public API and may change.

#### Usage

    mkdir build && cd build
    cmake ..
    make
    ./libwireshark-example1 -f ../test/1.pcap
    ./libwireshark-example2 -f ../test/http.pcap

#### License

Code is released under same terms as [tshark](https://github.com/boundary/wireshark/blob/master/tshark.c), which it's based on (GNU GPL2.0+). It contains [code by Sun Wang](https://github.com/sunwxg/decode_by_libwireshark), originally under the MIT license.
