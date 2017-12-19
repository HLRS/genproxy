% GENPROXY(1) genproxy 2.0 | User Commands
% Jan Just Keijser (Nikhef), Frank Scheiner (HLRS)
% Dec 19, 2017


# NAME #

**genproxy** - create GSI proxy credentials with just OpenSSL and a POSIX compatible shell


# SYNOPSIS #

**genproxy [options]**


# DESCRIPTION #

**genproxy** is a POSIX shell script that can be used to generate GSI proxy credentials (GPCs) like **grid-proxy-init(1)** but with just **openssl(1)** and without the need for the Globus Toolkit itself.


# OPTIONS #

The options are as follows:

## **[\--help]** ##

Display susage.


## **[-V, \--version]** ##

Displays version.


## **[\--debug]** ##

Enables extra output.


## **[-q, \--quiet]** ##

Quiet mode, minimal output.


## **[\--limited]** ##

Creates a limited GSI proxy credential.


## **[\--old]** ##

Creates a legacy globus proxy.


## **[\--gt3]** ##

Creates a pre-RFC3820 compliant proxy.


## **[\--rfc]** ##

Creates a RFC3820 compliant proxy (default).


## **[-d, \--days=N]** ##

Number of days the proxy is valid (default=1).


## **[\--pcpl=N, \--path-length=N]** ##

Allow a chain of at most N proxies to be generated from this one (default=-1, which is evaluated as unlimited).


## **[-b, \--bits=N]** ##

Number of bits in key (512, 1024, 2048, default=1024).


## **[--shaN]** ##

SHA algorithm to use for the digest (e.g. 1 (for SHA1), 256 (for SHA256), etc., default=256).


## **[\--cert=certfile]** ##

Non-standard location of user certificate.


## **[\--key=keyfile]** ##

Non-standard location of user key.


## **[-o, \--out=proxyfile]** ##

Non-standard location of new proxy cert.


# ENVIRONMENT VARIABLES #

## **X509_USER_PROXY** ##

By default the genproxy tool uses a "non-guessable" name for the generated GPC (created with **mktemp(1)**). This is important on multi-user hosts because otherwise symlink attacks are possible in _/tmp_ which can expose the GPC to other users. If you're running genproxy from a single user host, as an alternative to the **--out** option, you can also predefine the path and name of the GPC in the environment variable **X509_USER_PROXY** (for example with **export X509_USER_PROXY="$HOME/.globus/mygpc"**). If both **X509_USER_PROXY** is set and the **--out** option is used, the latter takes precedence!


# FILES #

## _$HOME/.globus/usercert.pem_ ##

Your personal X.509 certificate.


## _$HOME/.globus/userkey.pem_ ##

The matching private key to your personal X.509 certificate.


# EXIT CODES #

## 1 ##

GPC could not be created.

## 2 ##

Temporary file for operation could not be created.

## 3 ##

User certificate file could not be read.

## 4 ##

Given credentials were invalid.


# SEE ALSO #

**openssl(1SSL)**, **grid-proxy-init(1)**, **mktemp(1)**
