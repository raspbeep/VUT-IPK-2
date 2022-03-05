# Simple HTTP server    

HTTP server written in C. Serves on a given port and returns: cpu name, hostname, current cpu load.

## Compilation

```
$ make
```

## Deployment

```
$ ./hinfosvc [PORT]
```

## Usage

#### Get current CPU usage in %. Calculated from two readings(1 second apart) of cpu information from `/proc/stat`.
```
$ curl localhost:PORT/load
```
#### Example output
``
42%
``

#### Get hostname of server machine from `/etc/hostname`.
```
$ curl localhost:PORT/hostname
```
#### Example output
``
fedora
``

#### Get CPU name and base frequency from `/proc/cpuinfo`.
```
$ curl localhost:PORT/cpu-name
```
#### Example output
``
Intel(R) Core(TM) i7-10610U CPU @ 1.80GHz
``

## Contact

Pavel Kratochvil - xkrato61@vutbr.cz

Project Link: [https://github.com/raspbeep/VUT-IPK-1](https://github.com/raspbeep/VUT-IPK-1)

