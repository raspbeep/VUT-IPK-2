# ipk-sniffer    

A packet sniffer and analysis tool written in C.

## Compilation

```
$ make all
```
## Usage
Basic usage with no further filtering:
```
$ ./ipk-sniffer -i network-interface-name
```

Show first 10 captured IPv4 TCP packets:
```
$ ./ipk-sniffer -i network-interface-name -n 10 --tcp --ipv4
```

In case you are not sure which network interface are present in your system:
`--help` flag will show you all available interfaces and hint for all filtering flags.
```
$ ./ipk-sniffer --help
```
## Contact
Pavel Kratochvil - xkrato61@vutbr.cz

Project Link: [https://github.com/raspbeep/VUT-IPK-2](https://github.com/raspbeep/VUT-IPK-2)
