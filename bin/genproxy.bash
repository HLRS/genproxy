#! /bin/bash
# $Id: genproxy,v 1.2 2008/11/10 14:43:39 janjust Exp $

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
    if [ -n "${DEBUG:-}" ]
    then
        echo -e "run_cmd: $@"
    fi
    if [ -n "${QUIET:-}" ]
    then
        cmd_output=`eval "$@" 2>&1`
        exitcode=$?
        if [ $exitcode -ne 0 ]
        then
            echo "$cmd_output" >&2
        fi
    else
        eval "$@"
        exitcode=$?
    fi
    return $exitcode
}


VERSION="genproxy version 1.1"
USAGE="\
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
		(--version|-v)	echo "$VERSION"
						exit 0
						;;
		(--debug)		DEBUG=1
						QUIET=
						;;
		(--quiet|-q)	QUIET=1
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

info "Starting proxy generation"

# Apply defaults
DAYS=${DAYS:-1}
#VALID=${VALID:-12:00}
PROXY_SUGGEST=/tmp/x509up_u`id -u`
PROXY="${X509_USERPROXY:-$PROXY_SUGGEST}"
# the next 3 variables are referenced from openssl.cnnf
export PROXY_PATHLENGTH=${PROXY_PATHLENGTH:-2}
export PROXY_POLICY=${PROXY_POLICY:-normal_policy}
export PROXY_STYLE=${PROXY_STYLE:-legacy_proxy}
X509_USERCERT=${X509_USERCERT:-$HOME/.globus/usercert.pem}
X509_USERKEY=${X509_USERKEY:-$HOME/.globus/userkey.pem}
BITS=${BITS:-512}

debug "Output File: $PROXY"

OPENSSL="/usr/bin/openssl"
vers="`$OPENSSL version 2> /dev/null`"
if [ "$vers" == "${vers#OpenSSL 0.9.8}" ]
then
    OPENSSL="/usr/bin/openssl"
    vers="`$OPENSSL version 2> /dev/null`"
fi
if [ "$vers" == "${vers#OpenSSL 0.9.8}" -a -x /opt/etoken-pro/bin/openssl ]
then
    OPENSSL="/opt/etoken-pro/bin/openssl"
    vers="`$OPENSSL version 2> /dev/null`"
fi
if [ "$vers" == "${vers#OpenSSL 0.9.8}" ]
then
    echo "WARNING: cannot find openssl 0.9.8 binary." >&2
    echo "WARNING: GT3/GT4/RFC3820 proxy generation might fail!" >&2
fi
debug "Using openssl command [$OPENSSL]"

export OPENSSL_CONF=`mktemp openssl.cnf.XXXXXX`
PROXYREQ=`mktemp proxyrequest.XXXXXX`
PROXYKEY=`mktemp proxykey.XXXXXX`
PROXYCERT=`mktemp proxykey.XXXXXX`
RND=`expr $RANDOM \* $RANDOM`

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

info "Certificate serial number: $SERIAL"

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
    cat $PROXYCERT $PROXYKEY $X509_USERCERT > "$PROXY"
    chmod 600 "$PROXY"

    # simple proxy validation
    end_date=`$OPENSSL x509 -noout -enddate -in "$PROXY" | sed 's/notAfter=//'`
    info "Your proxy is valid until: `date -d \"$end_date\"`"
fi

rm $OPENSSL_CONF $PROXYCERT $PROXYKEY $PROXYREQ

exit $exitcode

