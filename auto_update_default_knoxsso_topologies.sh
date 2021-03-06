#!/usr/bin/env bash

#
# Script Name	  : auto_update_default_knoxsso_topologies.sh
# Description	  : This Script is developed to update default.xml & knoxsso.xml topologies with LDAP details
# Author        : Gulshad Ansari
# LinkedIn      : https://linkedin.com/in/gulshad/
#

yum clean all
yum install jq -y

LOC=`pwd`
source $LOC/cluster.properties

#------------------------------------------------------------------------------------
function checkforTarget () {
   if [ ! -f $_TARGETSCRIPT ]; then
      echo "$(date) Missing ($_TARGETSCRIPT). Make sure you execute this script from ambari-server node"
      exit 1
   fi
}

# update Default Topology file
function updateDefaultTopology () {
cat > /tmp/default.json <<EOFILE
{
  "properties": {
    "content": "<topology>\n    <gateway>\n        <provider>\n            <role>authentication</role>\n            <name>ShiroProvider</name>\n            <enabled>true</enabled>\n            <param>\n                <name>sessionTimeout</name>\n                <value>30</value>\n            </param>\n            <!-- LDAP Setting Start  -->\n            <param>\n                <name>main.ldapRealm</name>\n                <value>org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm</value>\n            </param>\n            <param>\n                <name>main.ldapContextFactory</name>\n                <value>org.apache.hadoop.gateway.shirorealm.KnoxLdapContextFactory</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.contextFactory</name>\n                <value>\$ldapContextFactory</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.contextFactory.url</name>\n                <value>$_LDAP_URL</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.contextFactory.systemUsername</name>\n                <value>$_LDAP_BIND_DN</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.contextFactory.systemPassword</name>\n                <value>$_LDAP_BIND_PASSWORD</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.contextFactory.authenticationMechanism</name>\n                <value>simple</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.searchBase</name>\n                <value>$_LDAP_SEARCH_BASE</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.userObjectClass</name>\n                <value>$_LDAP_userObjectClass</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.userSearchAttributeName</name>\n                <value>$_LDAP_userSearchAttributeName</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.authorizationEnabled</name>\n                <value>true</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.groupSearchBase</name>\n                <value>$_LDAP_SEARCH_BASE</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.groupObjectClass</name>\n                <value>$_LDAP_groupObjectClass</value>\n            </param>\n            <param>\n                <name>main.ldapRealm.groupIdAttribute</name>\n                <value>$_LDAP_groupIdAttribute</value>\n            </param>\n            <!-- LDAP Setting End  -->\n            <param>\n                <name>urls./**</name>\n                <value>authcBasic</value>\n            </param>\n        </provider>\n        <provider>\n            <role>identity-assertion</role>\n            <name>Default</name>\n            <enabled>true</enabled>\n        </provider>\n        <!-- Knox Authorization - Managed By Knox ACL -->\n        <provider>\n            <role>authorization</role>\n            <name>AclsAuthz</name>\n            <enabled>true</enabled>\n        </provider>\n    </gateway>\n    <service>\n        <role>NAMENODE</role>\n        <url>{{namenode_address}}</url>\n    </service>\n    <service>\n        <role>JOBTRACKER</role>\n        <url>rpc://{{rm_host}}:{{jt_rpc_port}}</url>\n    </service>\n    <service>\n        <role>WEBHDFS</role>\n                {{webhdfs_service_urls}}\n    \n    </service>\n    <service>\n        <role>WEBHCAT</role>\n        <url>http://{{webhcat_server_host}}:{{templeton_port}}/templeton</url>\n    </service>\n    <service>\n        <role>OOZIE</role>\n        <url>http://{{oozie_server_host}}:{{oozie_server_port}}/oozie</url>\n    </service>\n    <!-- UI Start-->\n    <service>\n        <role>OOZIEUI</role>\n        <url>http://{{oozie_server_host}}:{{oozie_server_port}}/oozie/</url>\n    </service>\n    <service>\n        <role>YARNUI</role>\n        <url>http://{{rm_host}}:{{rm_port}}</url>\n    </service>\n    <service>\n        <role>JOBHISTORYUI</role>\n        <url>http://{{rm_host}}:19888</url>\n    </service>\n    <!-- UI End-->\n    <service>\n        <role>WEBHBASE</role>\n        <url>http://{{hbase_master_host}}:{{hbase_master_port}}</url>\n    </service>\n    <service>\n        <role>HIVE</role>\n        <url>http://{{hive_server_host}}:{{hive_http_port}}/{{hive_http_path}}</url>\n    </service>\n    <service>\n        <role>RESOURCEMANAGER</role>\n        <url>http://{{rm_host}}:{{rm_port}}/ws</url>\n    </service>\n<service>\n    <role>ZEPPELINWS</role>\n                {{zeppelin_ws_urls}}\n    \n</service>\n</topology>"
  }
}
EOFILE
echo "Updated default.xml with ldap details"
}

# update Knox SSO Topology file
function updateKnoxSSOTopology () {
cat > /tmp/knoxsso.json <<EOFILE
{
  "properties": {
    "content": "<topology>\n<gateway>\n<provider>\n<role>webappsec</role>\n<name>WebAppSec</name>\n<enabled>true</enabled>\n<param>\n<name>xframe.options.enabled</name>\n<value>true</value>\n</param>\n</provider>\n<provider>\n<role>authentication</role>\n<name>ShiroProvider</name>\n<enabled>true</enabled>\n<param>\n<name>sessionTimeout</name>\n<value>30</value>\n</param>\n<param>\n<name>redirectToUrl</name>\n<value>/gateway/knoxsso/knoxauth/login.html</value>\n</param>\n<param>\n<name>restrictedCookies</name>\n<value>rememberme,WWW-Authenticate</value>\n</param>\n<param>\n<name>main.ldapRealm</name>\n<value>org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm</value>\n</param>\n<param>\n<name>main.ldapContextFactory</name>\n<value>org.apache.hadoop.gateway.shirorealm.KnoxLdapContextFactory</value>\n</param>\n<param>\n<name>main.ldapRealm.contextFactory</name>\n<value>\$ldapContextFactory</value>\n</param>\n<param>\n<name>main.ldapRealm.contextFactory.url</name>\n<value>$_LDAP_URL</value>\n</param>\n<param>\n<name>main.ldapRealm.contextFactory.systemUsername</name>\n<value>$_LDAP_BIND_DN</value>\n</param>\n<param>\n<name>main.ldapRealm.contextFactory.systemPassword</name>\n<value>$_LDAP_BIND_PASSWORD</value>\n</param>\n<param>\n<name>main.ldapRealm.contextFactory.authenticationMechanism</name>\n<value>simple</value>\n</param>\n<param>\n<name>main.ldapRealm.searchBase</name>\n<value>$_LDAP_SEARCH_BASE</value>\n</param>\n<param>\n<name>main.ldapRealm.userObjectClass</name>\n<value>$_LDAP_userObjectClass</value>\n</param>\n<param>\n<name>main.ldapRealm.userSearchAttributeName</name>\n<value>$_LDAP_userSearchAttributeName</value>\n</param>\n<param>\n<name>main.ldapRealm.authorizationEnabled</name>\n<value>false</value>\n</param>\n<param>\n<name>main.ldapRealm.groupSearchBase</name>\n<value>$_LDAP_SEARCH_BASE</value>\n</param>\n<param>\n<name>main.ldapRealm.groupObjectClass</name>\n<value>$_LDAP_groupObjectClass</value>\n</param>\n<param>\n<name>main.ldapRealm.groupIdAttribute</name>\n<value>$_LDAP_groupIdAttribute</value>\n</param>\n<!--\n<param>\n<name>main.ldapRealm.userDnTemplate</name>\n<value>uid={0},ou=people,dc=hadoop,dc=apache,dc=org</value>\n</param>\n<param>\n<name>main.ldapRealm.contextFactory.url</name>\n<value>ldap://localhost:33389</value>\n</param>\n-->\n<param>\n<name>main.ldapRealm.authenticationCachingEnabled</name>\n<value>false</value>\n</param>\n<param>\n<name>urls./**</name>\n<value>authcBasic</value>\n</param>\n</provider>\n<provider>\n<role>identity-assertion</role>\n<name>Default</name>\n<enabled>true</enabled>\n</provider>\n</gateway>\n\n<application>\n<name>knoxauth</name>\n</application>\n<service>\n<role>KNOXSSO</role>\n<param>\n<name>knoxsso.cookie.secure.only</name>\n<value>false</value>\n</param>\n<param>\n<name>knoxsso.token.ttl</name>\n<value>36000000</value>\n</param>\n<param>\n<name>knoxsso.redirect.whitelist.regex</name>\n<value>^https?:\\\/\\\/((.*)\\\.coelab\\\.cloudera\\\.com|localhost|127\\\.0\\\.0\\\.1|0:0:0:0:0:0:0:1|::1):[0-9].*\$</value>\n</param>\n</service>\n</topology>"
  }
}
EOFILE
echo "Updated knoxsso.xml with ldap details"
}


# Backup Original files
function backupOrigFiles () {
${_CMD} -a get -c knoxsso-topology -f /tmp/knoxsso.json.orig
sleep 5
${_CMD} -a get -c topology -f /tmp/default.json.orig
echo "Backup created for default.xml and knoxsso.xml : /tmp/default.json.orig /tmp/knoxsso.json.orig "
}

# Update New Files
function updateNewFiles () {
${_CMD} -a set -c knoxsso-topology -f /tmp/knoxsso.json
sleep 5
${_CMD} -a set -c topology -f /tmp/default.json
echo "default.xml and knoxsso.xml updated successfull"
}

function restartKnox () {
# Stop Knox
curl -k -u $_AMBARI_ADMIN_USER:$_AMBARI_ADMIN_PASSWORD -H 'X-Requested-By: ambari'  $_AMBARI_API/clusters/$_CLUSTER_NAME/services/KNOX -X PUT \
-d '{"RequestInfo": {"context" :"Stop Knox - Gulshad"}, "Body": {"ServiceInfo": {"state": "INSTALLED"}}}'

sleep 15
# Start Knox
curl -k -u $_AMBARI_ADMIN_USER:$_AMBARI_ADMIN_PASSWORD -H 'X-Requested-By: ambari'  $_AMBARI_API/clusters/$_CLUSTER_NAME/services/KNOX -X PUT \
-d '{"RequestInfo": {"context" :"Start Knox - Gulshad"}, "Body": {"ServiceInfo": {"state": "STARTED"}}}'

echo "\nRestarting Knox.......\n"
echo "check status on Ambari UI"
}


# Action Start Here
checkforTarget
updateDefaultTopology
updateKnoxSSOTopology
backupOrigFiles
updateNewFiles
restartKnox
# End of Script
