# Indoor positioning system (Access Point)

This project is an indoor positioning system aimed at locating users within a building using Wi-Fi. The project consists in three programs :
- [The Android application](https://github.com/FlorianeEnnaji/indoor-positioning-system-android) : The Android application sends packets to the server.
- The Access Point program (here) : The wi-fi access points are capturing those packets using libpcap. They are then sending requests to the server containing the RSSI (Signal Strength) of the packets captured.
- [The server (written in Node.JS)](https://github.com/FlorianeEnnaji/indoor-positioning-system-server) : The server then uses thoses requests, compare them to a fingerprint database, compute the user's location and send it back to the user.

## Requirements

The Wi-Fi access points used to develop this project are TP-Link N600 TL-WDR3600. They are running OpenWRT 14.07 as their operating system. Downloading the right SDK and toolchain (cross compilation) from the OpenWRT website should allow this project to be ported run on other wi-fi access points.

For the TP-Link N600, you need to download the SDK (OpenWrt-SDK-ar71xx-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2.tar.bz2)
and toolchain (OpenWrt-Toolchain-ar71xx-for-mips_34kc-gcc-4.8-linaro_uClibc-0.9.33.2.tar.bz2) from the [OpenWRT 14.07 ar71xx Download page](https://downloads.openwrt.org/barrier_breaker/14.07/ar71xx/generic/)

## Installation

The Makefile specifies in the PREFIX variable where those two elements have been extracted. By default, they are located in a "staging_dir" folder next to the project's root folder.

Make sure libpcap is installed on the Access points.

To build, just do :
```
$ make
```

Then copy the binary obtained over to the Access Point using for example :
```
$ scp ./ips-ap root@IP-Access-Point:/root
```

Once the binary is on the target, connect to it using SSH or other method and launch the program :
```
# ./ips-ap
```
If you want to filter packets on a specific MAC address, you can pass it in the form of XX:XX:XX:XX:XX:XX as an optional first argument.
