# How to generate proxy certificates #

The genproxy script can be used to generate a globus-style proxy. This script

* is written as a bash shell script
* Uses only openssl commands to generate a proxy.
* requires openssl 0.9.8 or higher to be installed in order to generate the new RFC3820 style proxy certificates.
* Uses none of the Globus toolkit itself.

Usage is as follows:

```
./genproxy --help
genproxy version 1.0
This script will generate a X509 grid proxy pretty much like globus' grid-proxy-init

  Options
  [--help]          Displays usage.
  [--version]       Displays version.
  [--debug]         Enables extra debug output.
  [--quiet]         Quiet mode, minimal output.
  [--limited]       Creates a limited globus proxy.
  [--old]           Creates a legacy globus proxy (default).
  [--gt3]           Creates a pre-RFC3820 compliant proxy.
  [--rfc]           Creates a RFC3820 compliant proxy.
  [--days=N]        Number of days the proxy is valid (default=1).
  [--path-length=N] Allow a chain of at most N proxies to be generated
                    from this one (default=2).
  [--bits=N]        Number of bits in key (512, 1024, 2048, default=512).
  [--cert=certfile] Non-standard location of user certificate.
  [--key=keyfile]   Non-standard location of user key.
  [--out=proxyfile] Non-standard location of new proxy cert.
```

This script was tested on CentOS 3 and 4, Fedora Core 5 and Windows XP using Cygwin. YMMV. Use at your own risk. 

Copyright (C) 2008 Jan Just Keijser, Nikhef
