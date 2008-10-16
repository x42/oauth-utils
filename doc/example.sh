#!/bin/sh
OAUTHSIGN=../src/oauthsign

#TOKENFILE=`mktemp /tmp/oauth.XXXXXXXXXX` || exit 1
TOKENFILE="/tmp/test.oaf"

CONKEY="key"
CONSEC="secret"
BASEURL="http://term.ie/oauth/example/"
DOPARAM=""
RQT="request_token.php"
ACT="access_token.php"
#AUT="authenticate.php?"
TST="echo_api.php?method=foo%20bar&bar=baz"


CONFIGFILE="./oauthconfX"
if [ -e $CONFIGFILE ]; then
 . $CONFIGFILE
fi

echo " +++ getting request token.."
$OAUTHSIGN -X -f $TOKENFILE -w -e -c $CONKEY -C $CONSEC "${BASEURL}${DOPARAM}${RQT}"

if [ -n "$AUT" ]; then
  REQTOK=$(cat $TOKENFILE | awk '/oauth_token_key=(.*)/{ print substr($1,17);}')
  echo "visit: ${BASEURL}${DOPARAM}${AUT}&oauth_token=${REQTOK}"
  echo -n "Authorize request token and press enter.."
  read 
  echo 
fi

echo " +++ exchanging request token for access token"
$OAUTHSIGN -X -f $TOKENFILE -w "${BASEURL}${DOPARAM}${ACT}" || ( echo "token exchange failed"; exit 1;) || exit 1;

echo " +++ making test request.."
$OAUTHSIGN -x -f $TOKENFILE "${BASEURL}${TST}"

echo " +++ and another one" 
$OAUTHSIGN -x -f $TOKENFILE -d "method=foo%&bar" -d "bar=foo bar" --post --dry-run "${BASEURL}echo_api.php"

# rm $TOKENFILE
