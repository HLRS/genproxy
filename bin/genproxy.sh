#!/usr/bin/env sh
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

debug()
{
    if [ -n "${DEBUG:-}" ]
    then
        # NetBSD's sh does not have an echo builtin and echo(1) only supports
        # `-n`. But the `-e` argument to echo seems to be at least ignored by
        # NetBSD's echo(1) but not by dash's echo builtin (sh is linked to dash
        # on Debian based Linux distributions). When used there with `-e`, the
        # argument is echoed instead, effectively prefixing all intended ouptut.
        # Hence we need to get along without `-e`.
        echo "$@"
    fi
}

info()
{
    if [ -z "${QUIET:-}" ]
    then
        echo "$@"
    fi
}

run_cmd()
{
    local exitcode=0
    if [ -n "${DEBUG:-}" ]
    then
        echo "run_cmd: $@"
        eval "$@" 1> "${MESSAGES}" 2>&1
        exitcode=$?
    else
        eval "$@" 1> "${MESSAGES}" 2>&1
        exitcode=$?
    fi
    return $exitcode
}

do_cleanup()
{
    # Use quotes around file names in case $TMP contains spaces
    rm -f "${OPENSSL_CONF}" "${TMP_USERCERT}" "${PROXYCERT}" "${PROXYKEY}" "${PROXYREQ}" "${MESSAGES}"
    # Needed as otherwise the terminal is screwed up after interrupting the "read" command
    stty sane
    return
}

abort()
{
    exitcode=$1
    shift
    echo "ERROR: $@ Aborting." 1>&2
    do_cleanup
    exit ${exitcode}
}

is_valid_file()
{
    local file="$1"

    if [ ! -e "$file" ]
    then
        debug "$file does not exist."
        return 1
    elif [ ! -f "$file" ]
    then
        debug "$file is not a regular file."
        return 1
    elif [ ! -s "$file" ]
    then
        debug "$file has zero size."
        return 1
    elif [ ! -r "$file" ]
    then
        debug "$file cannot be read."
        return 1
    else
        return 0
    fi
}

is_ascii_text_file()
{
    local file="$1"
    local file_type=""

    file_type=`file $file | cut -d ' ' -f 2-`

    if [ "$file_type" = "ASCII text" ]
    then
        return 0
    else
        return 1
    fi
}

###############################################################################
# MAIN
###############################################################################

TRUE=1
FALSE=0

VERSION="genproxy version 2.0"
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
                    from this one (default=-1, which is evaluated as unlimited).
  [--bits=N]        Number of bits in key (512, 1024, 2048, default=1024).
  [--shaN]          SHA algorithm to use for the digest (e.g. 1 (for SHA1),
                    256 (for SHA256), etc., default=256).
  [--cert=certfile] Non-standard location of user certificate or PKCS#12 file.
  [--key=keyfile]   Non-standard location of user key.
  [--out=proxyfile] Non-standard location of new proxy cert.

"

DEBUG=
QUIET=

while [ $# -gt 0 ]
do
    case "$1" in
		--days|-d)		DAYS=$2
#					VALID=`expr 24 \* $DAYS`:00
					shift
					;;
		--days=*)		DAYS=${1##--days=}
#					VALID=`expr 24 \* $DAYS`:00
					;;
#		--valid)		VALID=$2
#					shift
#					;;
#		--valid=*)		VALID=${1##--valid=}
#					;;
		--cert)			X509_USERCERT=$2
					shift
					;;
		--cert=*)		X509_USERCERT=${1##--cert=}
					;;
		--key)			X509_USERKEY=$2
					shift
					;;
		--key=*)		X509_USERKEY=${1##--key=}
					;;
		--out|-o)		X509_USERPROXY=$2
					shift
					;;
		--out=*)		X509_USERPROXY=${1##--out=}
					;;
		--pcpl)			PROXY_PATHLENGTH=$2
					shift
					;;
		--pcpl=*)		PROXY_PATHLENGTH=${1##--pcpl=}
					;;
		--path-length)		PROXY_PATHLENGTH=$2
					shift
					;;
		--path-length=*)	PROXY_PATHLENGTH=${1##--path-length=}
					;;
		--version|-V)		echo "$VERSION"
					exit 0
					;;
		--debug)		DEBUG=1
					QUIET=
					;;
		--quiet|-q)		QUIET=1
					DEBUG=
					;;
		--limited)		PROXY_POLICY=limited_policy
					;;
		--old)			PROXY_STYLE=legacy_proxy
					;;
		--gt3)			PROXY_STYLE=globus_proxy
					;;
		--rfc)			PROXY_STYLE=rfc3820_proxy
					;;
		--bits|-b)		BITS=$2
					shift
					;;
		--bits=*)		BITS=${1##--bits=}
					;;
		--sha*)			SHA_ALG=${1##--}
					;;
		*)			echo "$VERSION"
					echo "$USAGE"
					exit 0
					;;
	esac
	shift
done

#info "Starting proxy generation"

# This is supported on NetBSD's sh, OpenBSD's pdksh and also on Debian's dash
# (although its manpage doesn't mention it!)
trap "do_cleanup" EXIT

# Apply defaults
DAYS=${DAYS:-1}
#VALID=${VALID:-12:00}
if [ ! -z "$X509_USERPROXY" ]
then
    PROXY="$X509_USERPROXY"
elif [ ! -z "$X509_USER_PROXY" ]
then
    PROXY="$X509_USER_PROXY"
else
    PROXY_SUGGEST="/tmp/x509up_u`id -u`"
    PROXY="$PROXY_SUGGEST"
fi
if [ "${PROXY_PATHLENGTH}EMPTY" = "EMPTY" ]
then
    # Default to unlimited path length (= -1)
    PROXY_PATHLENGTH="-1"
fi
PROXY_POLICY=${PROXY_POLICY:-normal_policy}
PROXY_STYLE=${PROXY_STYLE:-rfc3820_proxy}
X509_P12CRED="${X509_USERCERT:-$HOME/.globus/usercred.p12}"
X509_USERCERT="${X509_USERCERT:-$HOME/.globus/usercert.pem}"
X509_USERKEY="${X509_USERKEY:-$HOME/.globus/userkey.pem}"
BITS=${BITS:-1024}
SHA_ALG=${SHA_ALG:-sha256}
OPENSSL="/usr/bin/openssl"

if [ "${X509_USER_CERT}EMPTY" = "EMPTY" ]
then
    if ! is_valid_file "$X509_USERCERT"
    then
        if ! is_valid_file "$X509_P12CRED"
        then
            abort 4 "Couldn't find valid credentials to generate a proxy. Neither \"${X509_USERCERT}\" nor \"${X509_P12CRED}\" are valid."
        fi
    fi
else
    if is_valid_file "$X509_USER_CERT"
    then
        X509_USERCERT="$X509_USER_CERT"
        if ! is_ascii_text_file "$X509_USER_CERT"
        then
            X509_P12CRED="$X509_USER_CERT"
        fi
    else
        abort 4 "Couldn't find valid credentials to generate a proxy. \"${X509_USER_CERT}\" (in X509_USER_CERT) is not valid."
    fi
fi

if [ "${X509_USER_KEY}EMPTY" = "EMPTY" ]
then
    if ! is_valid_file "$X509_USERKEY"
    then
        if is_ascii_text_file "$X509_USERCERT"
        then
            abort 4 "Couldn't find valid credentials to generate a proxy. \"${X509_USERKEY}\" is not valid."
        fi
    fi
else
    if is_valid_file "$X509_USER_KEY"
    then
        if is_ascii_text_file "$X509_USER_KEY"
        then
            X509_USERKEY="$X509_USER_KEY"
        fi
    else
        abort 4 "Couldn't find valid credentials to generate a proxy. \"${X509_USER_KEY}\" (in X509_USER_KEY) is not valid."
    fi
fi

unset TMP_USERCERT

debug "Output File: $PROXY"

# Check if we already own the proxy file. If not, check that we can create it
if [ ! -O "${PROXY}" ]
then
    rm -f "${PROXY}" && touch "${PROXY}"
    if [ $? -ne 0 ]
    then
        abort 1 "Cannot create proxy file '${PROXY}'."
    fi
fi
# Explicitly set permission on the output proxy
chmod 600 "${PROXY}"

# Do not attempt "export MESSAGES=`mktemp...`" as it drowns out all errorcodes
MESSAGES=`mktemp -p "/tmp" messages.XXXXXX`
if [ $? -ne 0 ]
then
    abort 2 "Could not create temporary file in ${TMP}."
fi
export MESSAGES

debug "running 'openssl x509 -noout -in $X509_USERCERT -subject'"
SUBJECT=`$OPENSSL x509 -noout -in "${X509_USERCERT}" -subject 2> /dev/null`
if [ $? -eq 0 ]
then
    use_pkcs12=$FALSE
else
    debug "$X509_USERCERT does not appear to be a valid PEM encoded certificate, trying PKCS#12"
    stty -echo
    echo -n "Enter GRID pass phrase for this identity:"
    read pkcs12pass
    stty echo
    echo ""
    TMP_USERCERT=`mktemp -p "/tmp" usercert.XXXXXX`
    $OPENSSL pkcs12 -in "${X509_P12CRED}" -clcerts -nokeys -out "${TMP_USERCERT}" -passin stdin 1>/dev/null 2>&1 <<EOF
${pkcs12pass}
EOF
    if [ $? -eq 0 ]
    then
        use_pkcs12=$TRUE
    else
        abort 3 "Could not read user certificate file '$X509_USERCERT'."
    fi
    SUBJECT=`$OPENSSL x509 -noout -in "${TMP_USERCERT}" -subject 2>/dev/null`
fi

debug "convert \"${SUBJECT}\" to a suitable format"
SUBJ=`echo "${SUBJECT}" | sed 's/subject= *//;s/\([A-Za-z0-9.]*\) = /\/\1=/;s/, \([A-Za-z0-9.]*\) = /\/\1=/g'`
info "Your identity: $SUBJ"

debug "running 'openssl x509 -noout -in $X509_USERCERT -serial'"
SERIAL=`$OPENSSL x509 -noout -in "${TMP_USERCERT:-$X509_USERCERT}" -serial 2>/dev/null | sed -e s'/serial= *//'`
debug "Certificate serial number: $SERIAL"

# Create temporary files
# Note that we need to export OPENSSL_CONF for the 'openssl req' command!
export OPENSSL_CONF=`mktemp -p "/tmp" openssl.cnf.XXXXXX`
PROXYREQ=`mktemp -p "/tmp" proxyrequest.XXXXXX`
PROXYKEY=`mktemp -p "/tmp" proxykey.XXXXXX`
PROXYCERT=`mktemp -p "/tmp" proxykey.XXXXXX`

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
    # for non-legacy proxies, the proxy policy (limited, normal) is implemented
    # using X509v3 extensions, which are loaded from the 'extfile'
    RND="0x`${OPENSSL} rand -hex 4`"
    PROXY_SUBJ="$RND"
    PROXY_SERIAL="$RND"
    PROXY_EXTENSIONS="-extfile ${OPENSSL_CONF}"
fi

if [ "$PROXY_PATHLENGTH" = "-1" ]
then
    # infinite path length
    rfc3820_seq_sect=`cat <<EOF
[ rfc3820_seq_sect ]
field2 = SEQUENCE:${PROXY_POLICY}
EOF
`
    globus_seq_sect=`cat <<EOF
[ globus_seq_sect ]
field1 = SEQUENCE:${PROXY_POLICY}
EOF
`
else
    # limited path length
    rfc3820_seq_sect=`cat <<EOF
[ rfc3820_seq_sect ]
field1 = INTEGER:${PROXY_PATHLENGTH}
field2 = SEQUENCE:${PROXY_POLICY}
EOF
`
    globus_seq_sect=`cat <<EOF
[ globus_seq_sect ]
field1 = SEQUENCE:${PROXY_POLICY}
field2 = EXPLICIT:1C,INTEGER:${PROXY_PATHLENGTH}
EOF
`
fi

# Create openssl.cnf on the fly ...
cat > $OPENSSL_CONF << EOF
extensions = ${PROXY_STYLE}

[ rfc3820_proxy ]
keyUsage = critical,digitalSignature,keyEncipherment
1.3.6.1.5.5.7.1.14 = critical,ASN1:SEQUENCE:rfc3820_seq_sect

${rfc3820_seq_sect}

[ globus_proxy ]
keyUsage = critical,digitalSignature,keyEncipherment
1.3.6.1.4.1.3536.1.222=critical,ASN1:SEQUENCE:globus_seq_sect

${globus_seq_sect}

[ normal_policy ]
p1 = OID:1.3.6.1.5.5.7.21.1

[ limited_policy ]
p1 = OID:1.3.6.1.4.1.3536.1.1.1.9

[ req ]
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
EOF

debug "DEBUG ENV ##########################################"
[ "$DEBUG" = "1" ] && env
debug "DEBUG ENV ##########################################"

run_cmd $OPENSSL req -new -nodes -keyout $PROXYKEY -out $PROXYREQ \
         -newkey rsa:$BITS -subj \"$SUBJ/CN=$PROXY_SUBJ\"

if [ $use_pkcs12 -eq $FALSE ]
then
    run_cmd $OPENSSL x509 -req \
      -in "${PROXYREQ}" \
      -CA "${X509_USERCERT}" \
      -CAkey "${X509_USERKEY}" \
      -out "${PROXYCERT}" \
      -set_serial ${PROXY_SERIAL} -${SHA_ALG} -days $DAYS \
      ${PROXY_EXTENSIONS}
else
    # we cannot use run_cmd with a "here" document
    $OPENSSL x509 -req \
      -in "${PROXYREQ}" \
      -CA "${TMP_USERCERT}" \
      -CAkey "${X509_P12CRED}" \
      -CAkeyform pkcs12 \
      -out "${PROXYCERT}" \
      -set_serial ${PROXY_SERIAL} -${SHA_ALG} -days $DAYS \
      ${PROXY_EXTENSIONS} \
      -passin stdin 1>/dev/null 2>&1 <<EOF
${pkcs12pass}
EOF
fi

exitcode=$?
# No longer needed, get rid of it ASAP
unset pkcs12pass

if [ $exitcode -eq 0 ]
then
    exitcode=$?
    cat "${PROXYCERT}" "${PROXYKEY}" "${TMP_USERCERT:-$X509_USERCERT}" > "$PROXY"

    # simple proxy validation
    end_date=`$OPENSSL x509 -noout -enddate -in "$PROXY" | sed 's/notAfter=//'`
    info "Your proxy \`$PROXY' is valid until: `date -d \"$end_date\"`"
else
    if grep 'unable to load CA Private Key' < $MESSAGES &>/dev/null
    then
        debug "`cat "${MESSAGES}"`"
        info "Error: Couldn't read user key in $X509_USERKEY."
        debug "Given pass phrase might be incorrect."
    fi
fi

do_cleanup
exit $exitcode
