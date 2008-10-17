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
CONKEY="key"
CONSEC="secret"
BASEURL="http://term.ie/oauth/example/"
DOPARAM=""
RQT="request_token.php"
ACT="access_token.php"
#AUT="authenticate.php?"
TST="echo_api.php?method=foo%20bar&bar=baz"

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
#echo " --- URL: ${BASEURL}${DOPARAM}${RQT}"
$OAUTHSIGN -X -f $TOKENFILE -w -e -c "$CONKEY" -C "$CONSEC" "${BASEURL}${DOPARAM}${RQT}" || ( echo " !!! no request token returned."; exit 1;) || exit 1;

if [ -n "$AUT" ]; then
  REQTOK=$(cat $TOKENFILE | awk '/oauth_token_key=(.*)/{ print substr($1,17);}')
  echo " +++ Authorization."
  echo "visit: ${BASEURL}${DOPARAM}${AUT}&oauth_token=${REQTOK}"
  echo -n "to authorize this request token and press enter.."
  read 
  echo 
fi

echo " +++ exchanging request token for access token"
$OAUTHSIGN -X -f $TOKENFILE -w "${BASEURL}${DOPARAM}${ACT}" --quiet || ( echo " !!! token exchange failed"; exit 1;) || exit 1;

echo " +++ making test request.."
$OAUTHSIGN -x -f $TOKENFILE "${BASEURL}${TST}" || ( echo " !!! test request failed"; exit 1;) || exit 1

echo " +++ and another one" 
$OAUTHSIGN -x -f $TOKENFILE -d "method=foo%&bar" -d "bar=foo bar" --post "${BASEURL}echo_api.php" || ( echo " !!! test request failed"; exit 1;) || exit 1

exit 0
