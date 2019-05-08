# Genproxy - create GSI proxy credentials with just OpenSSL and a POSIX compatible shell #

The `genproxy` script can be used to generate a GSI proxy credential (GPC) just like `grid-proxy-init`. But this script:

* is written as a POSIX shell script
* uses only OpenSSL commands to generate a proxy
* uses none of the Globus Toolkit itself
* is tested to work on GNU/Linux, OpenBSD and NetBSD

Usage is as follows:

```
$ ./genproxy --help
genproxy version 2.1
This script will generate a GSI proxy credential pretty much like globus' grid-proxy-init

  Options
  [--help]          Displays usage.
  [--version]       Displays version.
  [--debug]         Enables extra debug output (you can specify it multiple times).
  [--quiet]         Quiet mode, minimal output.
  [--limited]       Creates a limited proxy.
  [--independent]   Creates a independent proxy.
  [--draft|--gt3]   Creates a draft (GSI-3) proxy.
  [--old]           Creates a legacy proxy.
  [--rfc]           Creates a RFC3820 compliant proxy (default).
  [--days=N]        Number of days the proxy is valid (default=1).
  [--path-length=N] Allow a chain of at most N proxies to be generated
                    from this one (default=-1, i.e. unlimited).
  [--bits=N]        Number of bits in key (512, 1024, 2048, default=1024).
  [--shaNUM]        SHA hashing strength to use (default=sha256).
  [--cert=certfile] Non-standard location of user certificate or PKCS#12 file.
  [--key=keyfile]   Non-standard location of user key.
  [--out=proxyfile] Non-standard location of new proxy cert.
```

Check the [genproxy(1)] manpage for further details.

[genproxy(1)]: /share/doc/genproxy.1.md

## License ##

(GPLv3)

Copyright (C) 2008-2017 Jan Just Keijser, Nikhef  
Copyright (C) 2016-2019 Frank Scheiner, HLRS, Universitaet Stuttgart

The software is distributed under the terms of the GNU General Public License

This software is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a [copy] of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

[copy]: /COPYING

