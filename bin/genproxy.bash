#! /bin/bash
# $Id: genproxy,v 1.2 2008/11/10 14:43:39 janjust Exp $
# $Id: genproxy,v 1.3 2016/08/16 fs $
# 2016-08-16 Frank Scheiner (HLRS):
# * Updated defaults
# * added printout of GSI proxy credential filename and path
# * changed handling of info and debug messages in the code
# * removed OpenSSL version check, assuming we will always use a version
#   >= 0.9.8
#
# New defaults:
# * 1024 bits for the generated private key of the GSI proxy credential
# * creates RFC 3820 compliant GSI proxy credentials
#
# $Id: genproxy,v 1.4 2016/10/13 fs $
# 2016-10-13 Frank Scheiner (HLRS):
# * output is now closer to output from `grid-proxy-init`
# * added error message for wrong passphrase (identical to error output
#   of `grid-proxy-init`)
#
# $Id: genproxy,v 1.5 2016/10/18 fs $
# 2016-10-18 Frank Scheiner (HLRS):
# * the generated GSI proxy credential (GPC) is now created by mktemp
#   beforehand to fight symlink attacks in `/tmp`. If needed the name
#   and path of the GPC can still be configured by using the environment
#   variable `X509_USER_PROXY`.
#
# $Id: genproxy,v 1.6 2017/07/12 fs $
# 2017-07-12 Frank Scheiner (HLRS)
# * Added copyright statement and license with consent of Jan Just Keijser
#   from 2017-07-06.
# * the "-o" option was deactivated by accident in v1.5. This option now
#   works again and takes precedence over the setting of the environment
#   variable `X509_USER_PROXY`.

:<<COPYRIGHT

Copyright (C) 2008 Jan Just Keijser, Nikhef
Copyright (C) 2016-2017 Frank Scheiner, HLRS, Universitaet Stuttgart

The program is distributed under the terms of the GNU General Public License

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

COPYRIGHT

###############################################################################
# FUNCTIONS
###############################################################################

function debug()
{
    if [ -n "${DEBUG:-}" ]
    then
        echo -e "$@"
    fi
}

function info()
{
    if [ -z "${QUIET:-}" ]
    then
        echo -e "$@"
    fi
}

function run_cmd()
{
    local exitcode=0
    if [ -n "${DEBUG:-}" ]
    then
        echo -e "run_cmd: $@"
	eval "$@" 1>$MESSAGES 2>&1
        exitcode=$?
    else
        eval "$@" 1>$MESSAGES 2>&1
        exitcode=$?
    fi
    return $exitcode
}

###############################################################################
# MAIN
###############################################################################

VERSION="genproxy version 1.6"
USAGE="\
This script will generate a GSI proxy credential pretty much like globus' grid-proxy-init

  Options
  [--help]          Displays usage.
  [--version]       Displays version.
  [--debug]         Enables extra debug output.
  [--quiet]         Quiet mode, minimal output.
  [--limited]       Creates a limited globus proxy.
  [--old]           Creates a legacy globus proxy.
  [--gt3]           Creates a pre-RFC3820 compliant proxy.
  [--rfc]           Creates a RFC3820 compliant proxy (default).
  [--days=N]        Number of days the proxy is valid (default=1).
  [--path-length=N] Allow a chain of at most N proxies to be generated
                    from this one (default=2).
  [--bits=N]        Number of bits in key (512, 1024, 2048, default=1024).
  [--cert=certfile] Non-standard location of user certificate.
  [--key=keyfile]   Non-standard location of user key.
  [--out=proxyfile] Non-standard location of new proxy cert.

"

DEBUG=
QUIET=

while [ $# -gt 0 ]
do
    case "$1" in
		(--days|-d)		DAYS=$2
#						VALID=`expr 24 \* $DAYS`:00
						shift
						;;
		(--days=*)		DAYS=${1##--days=}
#						VALID=`expr 24 \* $DAYS`:00
						;;
#		(--valid)		VALID=$2
#						shift
#						;;
#		(--valid=*)		VALID=${1##--valid=}
#						;;
		(--cert)		X509_USERCERT=$2
						shift
						;;
		(--cert=*)		X509_USERCERT=${1##--cert=}
						;;
		(--key)			X509_USERKEY=$2
						shift
						;;
		(--key=*)		X509_USERKEY=${1##--key=}
						;;
		(--out|-o)		X509_USERPROXY=$2
						shift
						;;
		(--out=*)		X509_USERPROXY=${1##--out=}
						;;
		(--pcpl)		PROXY_PATHLENGTH=$2
						shift
						;;
		(--pcpl=*)		PROXY_PATHLENGTH=${1##--pcpl=}
						;;
		(--path-length)		PROXY_PATHLENGTH=$2
						shift
						;;
		(--path-length=*)	PROXY_PATHLENGTH=${1##--path-length=}
						;;
		(--version|-V)		echo "$VERSION"
						exit 0
						;;
		(--debug)		DEBUG=1
						QUIET=
						;;
		(--quiet|-q)		QUIET=1
						DEBUG=
						;;
		(--limited)		PROXY_POLICY=limited_policy
						;;
		(--old)			PROXY_STYLE=legacy_proxy
						;;
		(--gt3)			PROXY_STYLE=globus_proxy
						;;
		(--rfc)			PROXY_STYLE=rfc3820_proxy
						;;
		(--bits|-b)		BITS=$2
						shift
						;;
		(--bits=*)		BITS=${1##--bits=}
						;;
	 	(*)				echo "$VERSION"
						echo "$USAGE"
						exit 0
						;;
	esac
	shift
done

#info "Starting proxy generation"

# Apply defaults
DAYS=${DAYS:-1}
#VALID=${VALID:-12:00}
if [[ ! -z "$X509_USERPROXY" ]]; then

	PROXY="$X509_USERPROXY"

elif [[ ! -z "$X509_USER_PROXY" ]]; then

	PROXY="$X509_USER_PROXY"
else
	PROXY_SUGGEST_START="x509up_p$$"
	PROXY_SUGGEST=$( mktemp --tmpdir="/tmp" ${PROXY_SUGGEST_START}.fileXXXXXX.1 )
	PROXY="$PROXY_SUGGEST"
fi
# the next 3 variables are referenced from openssl.cnnf
export PROXY_PATHLENGTH=${PROXY_PATHLENGTH:-2}
export PROXY_POLICY=${PROXY_POLICY:-normal_policy}
export PROXY_STYLE=${PROXY_STYLE:-rfc3820_proxy}
X509_USERCERT=${X509_USERCERT:-$HOME/.globus/usercert.pem}
X509_USERKEY=${X509_USERKEY:-$HOME/.globus/userkey.pem}
BITS=${BITS:-1024}

debug "Output File: $PROXY"

OPENSSL="/usr/bin/openssl"

export OPENSSL_CONF=`mktemp openssl.cnf.XXXXXX`
PROXYREQ=`mktemp proxyrequest.XXXXXX`
PROXYKEY=`mktemp proxykey.XXXXXX`
PROXYCERT=`mktemp proxykey.XXXXXX`
RND=`expr $RANDOM \* $RANDOM`
export MESSAGES=$( mktemp messages.XXXXXX )

# Create openssl.cnf on the fly ...
cat > $OPENSSL_CONF << EOF
extensions = \$ENV::PROXY_STYLE

[ rfc3820_proxy ]
keyUsage = critical,digitalSignature,keyEncipherment
1.3.6.1.5.5.7.1.14 = critical,ASN1:SEQUENCE:rfc3820_seq_sect

[ rfc3820_seq_sect ]
field1 = INTEGER:\$ENV::PROXY_PATHLENGTH
field2 = SEQUENCE:\$ENV::PROXY_POLICY

[ globus_proxy ]
keyUsage = critical,digitalSignature,keyEncipherment
1.3.6.1.4.1.3536.1.222=critical,ASN1:SEQUENCE:globus_seq_sect

[ globus_seq_sect ]
field1 = SEQUENCE:\$ENV::PROXY_POLICY
field2 = EXPLICIT:1C,INTEGER:\$ENV::PROXY_PATHLENGTH

[ normal_policy ]
p1 = OID:1.3.6.1.5.5.7.21.1

[ limited_policy ]
p1 = OID:1.3.6.1.4.1.3536.1.1.1.9

[ req ]
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
EOF

debug "running 'openssl x509 -noout -in $X509_USERCERT -subject'"
SUBJ=`$OPENSSL x509 -noout -in $X509_USERCERT -subject | sed -e s'/subject= //'`
info "Your identity: $SUBJ"

debug "running 'openssl x509 -noout -in $X509_USERCERT -serial'"
SERIAL=`$OPENSSL x509 -noout -in $X509_USERCERT -serial | sed -e s'/serial=//'`

debug "Certificate serial number: $SERIAL"

if [ "$PROXY_STYLE" = "legacy_proxy" ]
then
    if [ "$PROXY_POLICY" = "normal_policy" ]
    then
        PROXY_SUBJ="proxy"
    else
        PROXY_SUBJ="limited proxy"
    fi
    PROXY_EXTENSIONS=""
    PROXY_SERIAL="0x$SERIAL"
else
    # for non-legacy proxies the proxy policy (limited, normal) is implemented
    # using X509v3 extensions, which are loaded from the 'extfile'
    PROXY_SUBJ="$RND"
    PROXY_EXTENSIONS="-extfile $OPENSSL_CONF"
    PROXY_SERIAL="$RND"
fi


run_cmd $OPENSSL req -new -nodes -keyout $PROXYKEY -out $PROXYREQ \
	-newkey rsa:$BITS -subj \"$SUBJ/CN=$PROXY_SUBJ\"

run_cmd $OPENSSL x509 -req \
         -in $PROXYREQ \
         -CA $X509_USERCERT \
         -CAkey $X509_USERKEY \
         -out $PROXYCERT \
         -set_serial $PROXY_SERIAL -sha1 -days $DAYS \
         $PROXY_EXTENSIONS
exitcode=$?

if [ $exitcode -eq 0 ]
then
    touch "$PROXY" && chmod 0600 "$PROXY"
    cat $PROXYCERT $PROXYKEY $X509_USERCERT > "$PROXY"

    # simple proxy validation
    end_date=`$OPENSSL x509 -noout -enddate -in "$PROXY" | sed 's/notAfter=//'`
    info "Your proxy \`$PROXY' is valid until: `date -d \"$end_date\"`"
else
	if grep 'unable to load CA Private Key' < $MESSAGES &>/dev/null; then

		debug "$( cat $MESSAGES )"
		info "Error: Couldn't read user key in $X509_USERKEY."
		debug "Given pass phrase might be incorrect."
	fi
fi

rm $OPENSSL_CONF $PROXYCERT $PROXYKEY $PROXYREQ $MESSAGES

exit $exitcode
