#!/bin/bash

CONFIGFILE=${1:-"./oauthconf"}

OAUTHSIGN=./src/oauthsign
if ! test -x $OAUTHSIGN; then
  OAUTHSIGN=../src/oauthsign
fi
if ! test -x $OAUTHSIGN; then
  OAUTHSIGN=$(which oauthsign)
fi
if ! test -x $OAUTHSIGN; then
  echo " oauthsign executable not found."
  exit 1
fi

# default config
OPT=""
CONKEY="key"
CONSEC="secret"
BASEURL="http://term.ie/oauth/example/"
DOPARAM=""
RQT="request_token.php"
ACT="access_token.php"
#AUT="authenticate.php?"
TST="echo_api.php"
TSQ="?method=foo%20bar&bar=baz"

if [ 1 == 0 ]; then     # test PLAINTEXT signature
  OPT="-m PLAINTEXT"
elif [ 1 == 0 ]; then   # test RSA-SHA1 signature
  OPT="-v -m RSA-SHA1"
  CONSEC="-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V
A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d
7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ
hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H
X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm
uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw
rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z
zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn
qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG
WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno
cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+
3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8
AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54
Lw03eHTNQghS0A==
-----END PRIVATE KEY-----"
fi

# read config file - override above settings
if [ -e $CONFIGFILE ]; then
 . $CONFIGFILE
fi

echo " --- oauthsign test and example"
echo " --- connecting to $BASEURL"

TOKENFILE=`mktemp /tmp/oauth.XXXXXXXXXX` || exit 1

function cleanup {
  rm $TOKENFILE
}
trap cleanup EXIT

echo " +++ getting request token.."
$OAUTHSIGN -X $OPT -f $TOKENFILE -w -e -c "$CONKEY" -C "$CONSEC" \
	"${BASEURL}${DOPARAM}${RQT}" \
	|| ( echo " !!! no request token returned."; exit 1;) || exit 1;

if [ -n "$AUT" ]; then
  REQTOK=$(cat $TOKENFILE | awk '/oauth_token_key=(.*)/{ print substr($1,17);}')
  echo " +++ Authorization."
  echo "visit: ${BASEURL}${DOPARAM}${AUT}&oauth_token=${REQTOK}"
  echo -n "to authorize this request token and press enter.."
  read 
  echo 
fi

echo " +++ exchanging request token for access token"
$OAUTHSIGN -X $OPT -f $TOKENFILE -w --quiet "${BASEURL}${DOPARAM}${ACT}" \
	|| ( echo " !!! token exchange failed"; exit 1;) || exit 1;

echo " +++ making test request.."
$OAUTHSIGN -x $OPT -f $TOKENFILE "${BASEURL}${TST}${TSQ}" \
	|| ( echo " !!! test request failed"; exit 1;) || exit 1

#echo " +++ and another one with parameter-arrays" 
#$OAUTHSIGN -x -f $TOKENFILE -d "foo=bar bar" \
#	-d 'bar[1]=foo&%bar' -d 'bar[0]=bar#+b a r' --post \
#	"${BASEURL}${TST}" \
#	|| ( echo " !!! test request failed"; exit 1;) || exit 1

exit 0
