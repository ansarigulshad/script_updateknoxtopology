#!/usr/bin/env bash

#
# Script Name	  : setup_zeppelin_sso.sh
# Description	  : Script to setup zeppelin authentication with knoxsso
# Author        : Gulshad Ansari
# LinkedIn      : https://linkedin.com/in/gulshad/
#

LOC=`pwd`
source $LOC/cluster.properties

function checkforTarget () {
   if [ ! -f $_TARGETSCRIPT ]; then
      echo "$(date) Missing ($_TARGETSCRIPT). Make sure you execute this script from ambari-server node"
      exit 1
   fi
}

# Retrieve knox certificate
function getKnoxCert () {
openssl s_client -connect ${_KNOX_HOST}:${_KNOX_PORT}  -showcerts  2>/dev/null </dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'  > /tmp/knox.pem
}

# Copy knox certificate to zeppelin host
function copyKnoxCertToZeppelinHost () {
scp /tmp/knox.pem  $_ZEPPELIN_HOST:/etc/zeppelin/conf/
if [ $? -eq 0 ]; then
        echo "knox certificate has been copied to zeppelin node successfully"
      else
        echo "Something went wrong, Kinldy copy /tmp/knox.pem to zeppelin host under /etc/zeppelin/conf/"
 fi
}

function backupShiro () {
${_CMD} -a get -c zeppelin-shiro-ini -f /tmp/shiro.ini.orig
echo "\n Back up created : /tmp/shiro.ini.orig"
}

function configureKnoxSSOforZeppelin () {
cat > /tmp/shiro.json <<EOFILE
{
  "properties": {
    "shiro_ini_content": "knoxJwtRealm = org.apache.zeppelin.realm.jwt.KnoxJwtRealm\nknoxJwtRealm.providerUrl = https://$_KNOX_HOST:$_KNOX_PORT/\nknoxJwtRealm.login = gateway/knoxsso/knoxauth/login.html\nknoxJwtRealm.publicKeyPath = /etc/zeppelin/conf/knox.pem\nknoxJwtRealm.logoutAPI = true\nknoxJwtRealm.logout = gateway/knoxssout/api/v1/webssout\nknoxJwtRealm.cookieName = hadoop-jwt\nknoxJwtRealm.redirectParam = originalUrl\nknoxJwtRealm.groupPrincipalMapping = group.principal.mapping\nknoxJwtRealm.principalMapping = principal.mapping\nauthc = org.apache.zeppelin.realm.jwt.KnoxAuthenticationFilter\n#passwordMatcher = org.apache.shiro.authc.credential.PasswordMatcher\n#iniRealm.credentialsMatcher = \$passwordMatcher\nsessionManager = org.apache.shiro.web.session.mgt.DefaultWebSessionManager\ncacheManager = org.apache.shiro.cache.MemoryConstrainedCacheManager\nsecurityManager.cacheManager = \$cacheManager\ncookie = org.apache.shiro.web.servlet.SimpleCookie\ncookie.name = JSESSIONID\ncookie.httpOnly = true\nsessionManager.sessionIdCookie = \$cookie\nsecurityManager.sessionManager = \$sessionManager\nsecurityManager.sessionManager.globalSessionTimeout = 86400000\nshiro.loginUrl = /api/login\n[urls]\n/** = authc"
  }
}
EOFILE

${_CMD} -a set -c zeppelin-shiro-ini -f /tmp/shiro.json
echo "\n Shiro.ini has been updated with knoxsso configurations"
sleep 5
}

function restartZeppelin () {
# Stop Knox
curl -k -u $_AMBARI_ADMIN_USER:$_AMBARI_ADMIN_PASSWORD -H 'X-Requested-By: ambari'  $_AMBARI_API/clusters/$_CLUSTER_NAME/services/ZEPPELIN -X PUT \
-d '{"RequestInfo": {"context" :"Stop Zeppelin - Gulshad"}, "Body": {"ServiceInfo": {"state": "INSTALLED"}}}'

sleep 20
# Start Knox
curl -k -u $_AMBARI_ADMIN_USER:$_AMBARI_ADMIN_PASSWORD -H 'X-Requested-By: ambari'  $_AMBARI_API/clusters/$_CLUSTER_NAME/services/ZEPPELIN -X PUT \
-d '{"RequestInfo": {"context" :"Start Knox - Gulshad"}, "Body": {"ServiceInfo": {"state": "STARTED"}}}'

echo "\n Restarting Zeppelin.......\n"
echo "Check status on Ambari UI"
}


# Action Start here
checkforTarget
getKnoxCert
copyKnoxCertToZeppelinHost
backupShiro
configureKnoxSSOforZeppelin
restartZeppelin

#End of Script
