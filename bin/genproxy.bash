#!//bin/bash
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
#
# $Id: genproxy,v 1.7 2017/07/13 fs $
# 2017-07-12 Jan Just Keijser (Nikhef):
# * Added support for other digest algorithms than SHA1.
# 2017-07-13 Frank Scheiner (HLRS):
# * Adapted help output.
#
# $Id: genproxy,v 1.8 2017/07/20 fs $
# 2017-07-20 Frank Scheiner (HLRS)
# * Added support for NetBSD's sh (POSIX shell)
#
# $Id: genproxy,v 1.9 2017/11/23 fs $
# 2017-11-23 Frank Scheiner (HLRS)
# * default to SHA256 for the digest algorithm
#
# $Id: genproxy,v 2.0 2017/11/27 janjust $
# 2017-11-27 Jan Just Keijser (Nikhef)
# * Added support for PKCS12 certificates
# * Ensured that it continues to work with OpenSSL 1.1
# * Added trap handler to clean up temp files
# 2017-11-30, 2017-12-05, 2017-12-14, 2017-12-19 Frank Scheiner (HLRS)
# * Incorporated and adapted changes by JJK into the POSIX shell version
# * Incorporated suggestions from MS
# * Added checks (e.g. for existence, etc.) for used credentials

:<<COPYRIGHT

Copyright (C) 2008-2017 Jan Just Keijser, Nikhef
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
    if [ ${DEBUG} -gt 0 ]
    then
        echo "$@"
    fi
}

function debug2()
{
    if [ ${DEBUG} -gt 1 ]
    then
        echo "$@"
    fi
}

function info()
{
    if [ ${QUIET} -eq 0 ]
    then
        echo "$@"
    fi
}

function do_cleanup()
{
    # Use quotes around file names in case $TMP contains spaces
    rm -f "${OPENSSL_CONF}" "${TMP_USER_CERT}" "${PROXYCERT}" "${PROXYKEY}" "${PROXYREQ}"
    if [ $remove_proxy_on_exit -eq 1 ]
    then
        rm -f "${PROXY}"
    fi
    # Needed as otherwise the terminal is screwed up after interrupting the "read" command
    stty sane
}

function abort()
{
    exitcode=$1
    shift
    echo "ERROR: $@. Aborting." 1>&2
    exit ${exitcode}
}


###############################################################################
# MAIN
###############################################################################

VERSION="genproxy version 2.0"
USAGE="\
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
                    from this one (default=2).
  [--bits=N]        Number of bits in key (512, 1024, 2048, default=1024).
  [--shaNUM]        SHA hashing strength to use (default=sha256).
  [--cert=certfile] Non-standard location of user certificate or PKCS#12 file.
  [--key=keyfile]   Non-standard location of user key.
  [--out=proxyfile] Non-standard location of new proxy cert.

"

DEBUG=0
QUIET=0

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
		(--cert)		X509_USER_CERT=$2
						shift
						;;
		(--cert=*)		X509_USER_CERT=${1##--cert=}
						;;
		(--key)			X509_USER_KEY=$2
						shift
						;;
		(--key=*)		X509_USER_KEY=${1##--key=}
						;;
		(--out|-o)		X509_USER_PROXY=$2
						shift
						;;
		(--out=*)		X509_USER_PROXY=${1##--out=}
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
		(--version|-V)	echo "$VERSION"
						exit 0
						;;
		(--debug)		let DEBUG=$DEBUG+1
						QUIET=0
						;;
		(--quiet|-q)	QUIET=1
						DEBUG=0
						;;
		(--limited)		PROXY_POLICY=limited_policy
						;;
		(--independent)	PROXY_POLICY=independent_policy
						;;
		(--old)			PROXY_STYLE=legacy_proxy
						;;
		(--draft)		PROXY_STYLE=globus_proxy
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
		(--sha*)		SHA_ALG=${1##--}
						;;
		(*)				echo "$VERSION"
						echo "$USAGE"
						exit 0
						;;
	esac
	shift
done

#info "Starting proxy generation"

trap do_cleanup   EXIT 

# Apply defaults
DAYS=${DAYS:-1}
#VALID=${VALID:-12:00}
TMP="${TMPDIR:-/tmp}"
PROXY_SUGGEST=${TMP}/x509up_u`id -u`
PROXY="${X509_USER_PROXY:-$PROXY_SUGGEST}"
PROXY_PATHLENGTH=${PROXY_PATHLENGTH:--1}
PROXY_POLICY=${PROXY_POLICY:-normal_policy}
PROXY_STYLE=${PROXY_STYLE:-rfc3820_proxy}
X509_P12CRED="${X509_USER_CERT:-$HOME/.globus/usercred.p12}"
X509_USER_CERT="${X509_USER_CERT:-$HOME/.globus/usercert.pem}"
X509_USER_KEY="${X509_USER_KEY:-$HOME/.globus/userkey.pem}"
BITS=${BITS:-1024}
SHA_ALG=${SHA_ALG:-sha256}
OPENSSL="/usr/bin/openssl"
#OPENSSL="/home/janjust/src/openssl-1.1.0g/apps/openssl"
key_format=pem
remove_proxy_on_exit=0

# check if the proxy policy and proxy style match
if [ "${PROXY_STYLE}" = "legacy_proxy" -a "${PROXY_POLICY}" = "independent_policy" ]
then
    abort 1 "Invalid legacy proxy type"
fi

unset TMP_USER_CERT

debug "User Cert File: $X509_USER_CERT"
debug "User Key File: $X509_USER_KEY"
debug ""
debug "Output File: $PROXY"

# Check if we already own the proxy file. If not, check that we can create it
if [ ! -O "${PROXY}" ]
then
    rm -f "${PROXY}" && touch "${PROXY}"
    if [ $? -ne 0 ]
    then
        abort 2 "Cannot create proxy file '${PROXY}'."
    fi
    remove_proxy_on_exit=1
fi
# Explicitly set permission on the output proxy
chmod 600 "${PROXY}"

TMP_USER_CERT=`mktemp "${TMP}/usercert.XXXXXX"`
if [ $? -ne 0 ]
then
    abort 3 "Could not create temporary file in ${TMP}."
fi

debug2 "running 'openssl x509 -noout -in $X509_USER_CERT -subject'"
SUBJECT=`$OPENSSL x509 -noout -in "${X509_USER_CERT}" -subject 2> /dev/null`
if [ $? -eq 0 ]
then
    # copy the file, as TMP_USER_CERT is removed upon exit
    cat "${X509_USER_CERT}" > "${TMP_USER_CERT}"
else
    debug2 "$X509_USER_CERT does not appear to be a valid PEM encoded certificate, trying PKCS#12"
    echo -n "Enter GRID pass phrase: "
    read -s gridpassphrase
    echo
    if [ $QUIET -eq 0 ]
    then
        $OPENSSL pkcs12 -in "${X509_P12CRED}" -clcerts -nokeys -out "${TMP_USER_CERT}" \
         -passin stdin <<< "${gridpassphrase}"
    else
        $OPENSSL pkcs12 -in "${X509_P12CRED}" -clcerts -nokeys -out "${TMP_USER_CERT}" \
         -passin stdin <<< "${gridpassphrase}" 2> /dev/null
    fi
    if [ $? -eq 0 ]
    then
        key_format=pkcs12
        X509_USER_KEY="${X509_P12CRED}"
    else
        abort 4 "Could not read user certificate file '$X509_USER_CERT'."
    fi
    SUBJECT=`$OPENSSL x509 -noout -in "${TMP_USER_CERT}" -subject`
fi
debug2 "convert \"${SUBJECT}\" to a suitable format"
SUBJ=`echo "${SUBJECT}" | sed 's/subject= *//;s/\([A-Za-z0-9.]*\) = /\/\1=/;s/, \([A-Za-z0-9.]*\) = /\/\1=/g'`
# grid-proxy-init always strips the /CN={proxy,limited proxy,NNNNNNNN} 
ident="${SUBJ%%/CN=proxy*}"
ident="${SUBJ%%/CN=limited proxy*}"
ident="${SUBJ%%/CN=[0-9][0-9][0-9][0-9]*}"
info "Your identity: ${ident}"

debug2 "running 'openssl x509 -noout -in $TMP_USER_CERT -serial'"
SERIAL=`$OPENSSL x509 -noout -in "${TMP_USER_CERT}" -serial | sed -e s'/serial= *//'`
debug2 "Certificate serial number: $SERIAL"

if [ "${key_format}" = "pem" ]
then
    # check if the private key has no passphrase
    # This is acceptable if we're generating a proxy from a proxy)
    debug2 "running 'openssl rsa -check -noout -in ${X509_USER_KEY} -passin stdin'"
    echo | openssl rsa -check -noout -in "${X509_USER_KEY}" -passin stdin > /dev/null 2>&1
    if [ $? -eq 0 ]
    then
        debug2 "private key has no passphrase, hopefully it's a proxy certificate"
        gridpassphrase=""
    else
        echo -n "Enter GRID pass phrase for this identity: "
        read -s gridpassphrase
        echo
    fi
fi

# Create temporary files
# Note that we need to export OPENSSL_CONF for the 'openssl req' command!
export OPENSSL_CONF=`mktemp ${TMP}/openssl.cnf.XXXXXX`
PROXYREQ=`mktemp "${TMP}/proxyrequest.XXXXXX"`
PROXYKEY=`mktemp "${TMP}/proxykey.XXXXXX"`
PROXYCERT=`mktemp "${TMP}/proxycert.XXXXXX"`
PROXY_EXTENSIONS="-extfile ${OPENSSL_CONF}"

if [ "$PROXY_STYLE" = "legacy_proxy" ]
then
    if [ "$PROXY_POLICY" = "normal_policy" ]
    then
        PROXY_SUBJ="proxy"
    else
        PROXY_SUBJ="limited proxy"
    fi
    PROXY_SERIAL="0x$SERIAL"
else
    # for non-legacy proxies, the proxy policy (limited, normal) is implemented
    # using X509v3 extensions, which are loaded from the 'extfile'
    RND=`expr $RANDOM \* $RANDOM`
    PROXY_SUBJ="$RND"
    PROXY_SERIAL="$RND"
    if [ ${PROXY_PATHLENGTH} -ge 0 ]
    then
        RFC_PROXY_PATHLENGTH="pathlen = ${PROXY_PATHLENGTH}"
        GSI_PROXY_PATHLENGTH="pathlen = EXPLICIT:1C,INTEGER:${PROXY_PATHLENGTH}"
    fi
fi


# Create openssl.cnf on the fly ...
cat > $OPENSSL_CONF << EOF
extensions = ${PROXY_STYLE}

[ legacy_proxy ]
extendedKeyUsage = clientAuth,emailProtection
keyUsage         = critical,digitalSignature,keyEncipherment,dataEncipherment

[ rfc3820_proxy ]
extendedKeyUsage = clientAuth,emailProtection
keyUsage         = critical,digitalSignature,keyEncipherment,dataEncipherment
1.3.6.1.5.5.7.1.14 = critical,ASN1:SEQUENCE:rfc3820_proxy_ext

[ rfc3820_proxy_ext ]
${RFC_PROXY_PATHLENGTH}
policy  = SEQUENCE:${PROXY_POLICY}

[ globus_proxy ]
extendedKeyUsage = clientAuth,emailProtection
keyUsage         = critical,digitalSignature,keyEncipherment,dataEncipherment
1.3.6.1.4.1.3536.1.222=critical,ASN1:SEQUENCE:globus_proxy_ext

[ globus_proxy_ext ]
policy  = SEQUENCE:${PROXY_POLICY}
${GSI_PROXY_PATHLENGTH}

[ normal_policy ]
p1 = OID:1.3.6.1.5.5.7.21.1

[ independent_policy ]
p1 = OID:1.3.6.1.5.5.7.21.2

[ limited_policy ]
p1 = OID:1.3.6.1.4.1.3536.1.1.1.9

[ req ]
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
EOF


debug2 "running 'openssl req -new -nodes -keyout ${PROXYKEY} -out ${PROXYREQ} \
    -newkey rsa:$BITS -subj \"$SUBJ/CN=$PROXY_SUBJ\"'"
if [ $QUIET -eq 0 ]
then
    $OPENSSL req -new -nodes -keyout "${PROXYKEY}" -out "${PROXYREQ}" \
     -newkey rsa:$BITS -subj "$SUBJ/CN=$PROXY_SUBJ"

    $OPENSSL x509 -req \
     -in "${PROXYREQ}" \
     -CA "${TMP_USER_CERT}" \
     -CAkey "${X509_USER_KEY}" \
     -CAkeyform "${key_format}" \
     -out "${PROXYCERT}" \
     -set_serial ${PROXY_SERIAL} -${SHA_ALG} -days $DAYS \
     ${PROXY_EXTENSIONS} \
     -passin stdin <<< "${gridpassphrase}"
else
    $OPENSSL req -new -nodes -keyout "${PROXYKEY}" -out "${PROXYREQ}" \
     -newkey rsa:$BITS -subj "$SUBJ/CN=$PROXY_SUBJ" 2> /dev/null

    $OPENSSL x509 -req \
     -in "${PROXYREQ}" \
     -CA "${TMP_USER_CERT}" \
     -CAkey "${X509_USER_KEY}" \
     -CAkeyform "${key_format}" \
     -out "${PROXYCERT}" \
     -set_serial ${PROXY_SERIAL} -${SHA_ALG} -days $DAYS \
     ${PROXY_EXTENSIONS} \
     -passin stdin <<< "${gridpassphrase}" 2> /dev/null
fi
exitcode=$?

# No longer needed, get rid of it
unset gridpassphrase

if [ $exitcode -eq 0 ]
then
    exitcode=$?
    cat "${PROXYCERT}" "${PROXYKEY}" "${TMP_USER_CERT}" > "$PROXY"
    # simple proxy validation
    end_date=`$OPENSSL x509 -noout -enddate -in "$PROXY" | sed 's/notAfter=//'`
    info "Your proxy \`$PROXY' is valid until: `date -d \"$end_date\"`"

    remove_proxy_on_exit=0
else
    info "Error: Couldn't read user key in $X509_USER_KEY."
    debug2 "Given pass phrase might be incorrect."
fi

