#!/bin/sh
#
# To the extent possible under law, Red Hat, Inc. has dedicated all copyright to this software to the public domain worldwide,
# pursuant to the CC0 Public Domain Dedication. This software is distributed without any warranty.
# See http://creativecommons.org/publicdomain/zero/1.0/
#
# This script generates a set of JKS keystores with mutual trust (2-way SSL) using a CA as well as a variety of other supporting files.
#
# It uses RSA for keys and SHA256withRSA for signing as default
#
# Key and Signature names: http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
#
# Author: Tom Fonteyne
#
VERSION="2016-06-09"
#
#set -x

# java version "xxx", so filter for the line first, then for a quote followed by number
# vs=`java -version 2>&1 | grep "java version" | grep -e "\"1\.7" -e "\"1\.8" -e "\"9" | head -1`
vs=`java -version 2>&1 | grep -P "(java|openjdk) version" | grep -e "\"1\.7" -e "\"1\.8" -e "\"9" | head -1`

if [ -z "${vs}" ]; then
  echo "This script needs Java 7 or up"
  exit
fi
# defaults: can be overridden by creating a file "~/.cli-config" with your personal values or with command line options

#----------------------------------------------------------------------------
# CA generation
CA_ALIAS="ca"

# the password for the keystore
STORE_PASSWORD=secret

#----------------------------------------------------------------------------
# the set of keyalg/size/sigalg *must* be compatible with each other.
# Using RSA gives the default of SHA256withRSA, here set explicitly as a reminder

# key algorithm
KEYALG="RSA"

# the size of the key in bits
KEYSIZE="2048"

# Signature algorithm
SIGALG="SHA256withRSA"

# The amount of days the certs should be valid
DAYS=3650 # 10 years

#----------------------------------------------------------------------------

# port for mod_cluster listener on the JBoss server
MOD_CLUSTER_PORT="6666"
# The name of the balancer as configured in JBoss mod_cluster subsystem
MOD_CLUSTER_BALANCER="jbossbalancer"

# we're using certs. Hence must be https, but the actual connector can be called differently. This script does not support AJP yet
MOD_CLUSTER_CONNECTOR="https"

# use advertizing or not
MOD_CLUSTER_ADVERTIZE="false"

# for use in domain mode. By default empty for standalone
PROFILE=

# the location where all the Apache related files need to go. The .conf files go into conf.d as normal of course.
APACHE_SSLDIR="conf.d/ssl"

# read the configuration file if there is one allowing you to override the above defaults with your own.

if [ -f "$HOME/.cli-config" ]; then
  source $HOME/.cli-config $1
fi

##############################
# Nothing to modify below here
##############################

set -e

function usage()
{
  echo "Generate Key and Trust stores for two way authentication - Author: Tom Fonteyne, version: $VERSION"
  echo " "
  echo "This script will generate all you need for full two way SSL communication including a CA"
  echo "It is meant as an example only, and you will likely want to use your own/existing CA instead,"
  echo "but it illustrates all commands needed"
  echo "Set the -v option to echo out all the keytool/openssl command as they execute"
  echo " "
  echo "Simple usage, generates a CA if none found + a server certificate for the host specified:"
  echo " "
  echo "  $0 [-v] -s <server> [-p password]"
  echo " "
  echo "Full usage:"
  echo " "
  echo "  $0 [-v] -s <server> [-sdn <server-dn>] -c <client> [-cdn <client-dn>]"
  echo "     [-ca <name>] [-cadn <ca-dn>] [-b <browser>] [-bdn <browser-dn>]"
  echo "     [-p <password>] [-d <days>]"
  echo "     [-ks <keysize>] [-ka <key-algorithm>] [-sa <signing-algorith>]"
  echo "     [-m] [-mcp <name>] [-mca]"
  echo " "
  echo "  -v    verbose, echo the actual commands to the console"
  echo " "
  echo "  -s 	fully qualified server host name, typically the JBoss EAP server"
  echo "  -sdn  the dname for the server host, normally not needed as you should be using the fully qualified server host name"
  echo "        default: cn=<-c value>"
  echo " "
  echo "  -c 	client host name, typically Apache, the JBoss CLI, or any other client or server which requires a 2-way SSL setup"
  echo "  -cdn  the dname for the client host"
  echo "        default: cn=<-c value>"
  echo " "
  echo "  -ca   name for the CA cert, if a keystore (jks) file with the CA name is found,"
  echo "        then this file will used."
  echo "        default: $CA_ALIAS"
  echo "  -cadn the dname for the CA"
  echo "        default: cn=$CA_ALIAS"
  echo " "
  echo "  -b    browser alias"
  echo "  -bdn  the name for the browser cert"
  echo "        default: cn=<-b value>"
  echo " "
  echo "  -p 	password for all certificates, key and truststores"
  echo "        default: $STORE_PASSWORD"
  echo "  -ks   the number of bits for the keysize"
  echo "        default: $KEYSIZE"
  echo "  -ka   key algorithm"
  echo "        default: $KEYALG"
  echo "  -sa   signing algorithm"
  echo "        default: $SIGALG"
  echo "  -d    number of days the certificate is valid"
  echo "        default: $DAYS"
  echo ""
  echo ""
  echo "  -m    generate mod_cluster, mod_proxy and SSL configuration files"
  echo ""
  echo "  -mcp   <name>    the jboss profile for use in domain mode"
  echo "                   default: standalone"
  echo "  -mca             whether to use advertizing"
  echo "                   default: use \"client host \" as the proxy list" 
  echo ""
  echo "   Note that this script is not very secure, as the password will be visible in a 'ps -ef' listing."
  echo " "
  echo " If a CA was not specified or no existing file found, then a default \"$CA_ALIAS\" will be created"
  echo " If you want the configuration files for modcluster etc, then you must specify both -s and -c"
  echo "   where -c specified the Apache server"
  echo " A browser certificate will only be created if you specify the -b option"
  echo " You can create additional server keystores/certs by simply specifying -s <name> on its own"
  exit
}

VERBOSE=false

# use to echo a command line before executing it, enable with the verbose option
function verbose()
{
  if [ "${VERBOSE}" == "true" ]; then
    echo "\$ $@" 
  fi
  "$@"
}

function checkArguments()
{
  if [ "$1" == "-?" -o "$1" == "-h" -o "$1" == "--help" ]; then
    usage
  fi

  while [ "$1" ]
  do
    case "$1" in
    -v)
      VERBOSE="true"
      shift;;
    -s)
      HOST1="$2"
      shift; shift;;
    -sdn)
      HOST1_DN="$2"
      shift; shift;;
      
    -c)
      HOST2="$2"
      shift; shift;;
    -cdn)
      HOST2_DN="$2"
      shift; shift;;
      
    -ca)
      CA_ALIAS="$2"
      shift; shift;;
    -cadn)
      CA_DN="$2"
      shift; shift;;
      
    -p)
      STORE_PASSWORD="$2"
      shift; shift;;

    -sa)
      SIGALG="$2"
      shift; shift;;
    -ka)
      KEYALG="$2"
      shift; shift;;
    -ks)
      KEYSIZE="$2"
      shift; shift;;

    -d)
      DAYS="$2"
      shift; shift;;

    -b)
      BROWSER="$2"
      BROWSER_DN="cn=$2"
      shift; shift;;
    -bdn)
      BROWSER_DN="cn=$2"
      shift; shift;;

    -m)
      GENERATE_MOD_FILES="true"
      shift;;

    -mcp)
      GENERATE_MOD_FILES="true"
      PROFILE="$2"
      shift; shift;;

    -mca)
      GENERATE_MOD_FILES="true"
      MOD_CLUSTER_ADVERTIZE="true"
      shift;;
      
     *)
      usage
      ;;
    esac
  done

  # use the name also for dname when dname is not set 
  if [ -z "$HOST1_DN" ]; then
    HOST1_DN="cn=$HOST1"
  fi
  if [ -z "$HOST2_DN" ]; then
    HOST2_DN="cn=$HOST2"
  fi
  if [ -z "$CA_DN" ]; then
    CA_DN="cn=$CA_ALIAS"
  fi
  if [ -z "$BROWSER_DN" ]; then
    BROWSER_DN="cn=$BROWSER"
  fi
  
  # either a server or a client must be specified.
  if [ -z "$HOST1" -a -z "$HOST2" -a -z "$CA_ALIAS" ]; then
    usage
  fi

  checkSigAlg "${KEYALG}" "${KEYSIZE}" "${SIGALG}"
  
if [ "$GENERATE_MOD_FILES" == "true" ]; then
    if [ -z "$HOST1" -o -z "$HOST2" ]; then
      echo "To generate mod configuration files, there must be a server (-s jbosshost) and a client (-c apachehost) specified"
      echo ""
      exit
    fi
  fi

  # prepare the profile prefix and configuration directory needed
  if [ -n "$PROFILE" ]; then
    PROFILE_PREFIX="/profile=$PROFILE"
    JBOSS_CONFDIR="\${jboss.domain.config.dir}"
  else
    JBOSS_CONFDIR="\${jboss.server.config.dir}"
  fi
}

# some *simple* checks, not exhaustive
function checkSigAlg()
{
  local keyalg="$1"
  local keysize="$2"
  local sigalg="$3"

  # http://docs.oracle.com/javase/7/docs/technotes/tools/solaris/keytool.html
  #
  # In generating a public/private key pair, the signature algorithm (-sigalg option) is derived from the algorithm of the underlying private key:
  #   If the underlying private key is of type "DSA", the -sigalg option defaults to "SHA1withDSA"
  #   If the underlying private key is of type "RSA", the -sigalg option defaults to "SHA256withRSA".
  #   If the underlying private key is of type "EC", the -sigalg option defaults to "SHA256withECDSA".

  # Replicated here with the sole purpose of showing the options explicitly
  case "${keyalg}" in
    RSA|rsa)
      SIGALG="SHA256withRSA"
      ;;
    DSA|dsa)
      SIGALG="SHA1withDSA"
      ;;
    EC|ec)
      SIGALG="SHA256withECDSA"
      ;;
    *)
      echo "Warning: unknown key algorithm ${keyalg}(${keysize}) using as-is with signature algorithm: ${sigalg} - this may not work"
      ;;
  esac
}

function genkeypairError()
{
  echo "Generating the keypair failed."
  echo "Hint: if the error was 'incorrect AVA format, then you entered an invalid dname(dn)."
  echo "DN's need to be of the format 'cn=name'"
  exit
}

STEP=1

##########################################################################################################
# generate our CA store, certs and keys
##########################################################################################################
function createOrFindCA()
{
  local ca_alias="$1"
  local ca_dn="$2"
  
  # if the CA keystore already exists, we use that one. Otherwise a new one will be created
  # we assume that all other CA related files are still there as well
  if [ -f "${ca_alias}.jks" ]; then
    return
  fi

  # -ext BasicConstraints:critical=ca:true
  #   BasicConstraints | bc
  #   critical | c
  #   ca:true can be ommited
  # the short form becomes then:
  #   -ext bc:c
  #
  echo -e "\e[00;31m$STEP. Generate the ca keystore with private key and certificate - key uses ${KEYSIZE} bits ${KEYALG}, and signature uses ${SIGALG}\e[00m"
  verbose keytool -genkeypair -keystore ${ca_alias}.jks -alias ${ca_alias} -ext BasicConstraints:critical=ca:true -dname "${ca_dn}" -storepass ${STORE_PASSWORD} -keyalg ${KEYALG} -keysize ${KEYSIZE} -sigalg ${SIGALG} -validity ${DAYS} -keypass ${STORE_PASSWORD}
  if [ "$?" == "1" ]; then
    genkeypairError 
  fi
  STEP=$(($STEP + 1))

  echo -e "\e[00;31m$STEP. Export the CA certificate to a file, for clients to import into their trust store\e[00m"
  verbose keytool -exportcert -alias ${ca_alias} -keystore ${ca_alias}.jks -storepass ${STORE_PASSWORD} -file ${ca_alias}.cer
  STEP=$(($STEP + 1))
  
  echo -e "\e[00;31m$STEP. convert the ca cert to pem format\e[00m" 
  verbose openssl x509 -inform der -in ${ca_alias}.cer -outform pem -out ${ca_alias}.pem
  STEP=$(($STEP + 1))
  
  echo -e "\e[00;31m$STEP. Create the common truststore with the CA certificate (so without key!) \e[00m"
  verbose keytool -importcert -keystore truststore.jks -storepass ${STORE_PASSWORD} -keypass ${STORE_PASSWORD} -alias ${ca_alias} -trustcacerts -file ${ca_alias}.cer -noprompt
  STEP=$(($STEP + 1))  
  
  echo -e "\e[00;31m$STEP. Converting CA JKS to PKCS12\e[00m"
  verbose keytool -importkeystore -srckeystore ${ca_alias}.jks -srcalias "${ca_alias}" -destkeystore "${ca_alias}.p12" -srcstoretype jks -deststoretype pkcs12 -srcstorepass ${STORE_PASSWORD} -deststorepass ${STORE_PASSWORD}
  
  CA_WAS_GENERATED=true
}

##########################################################################################################
# generate a keystore for the host and a signing request. Sign that with the CA and re-import
##########################################################################################################
function generateHost()
{
  local host=$1
  local dname=$2

  # Aside of setting the hostname in the dname, we explicitly set it as the SubjectAlternativeName so the cn attribute can be used freely for identification only if desired. 
  # 'SubjectAlternativeName' can be abreviated as 'san'
  # note: instead of 'dns' you can also use 'ip' to set an actual ip address. 'san' takes a comma separated list. 
  echo -e "\e[00;31m$STEP. Generating keystore for ${host} - key uses ${KEYALG}, and signature uses ${SIGALG}\e[00m"
  verbose keytool -genkeypair -alias ${host} -ext SubjectAlternativeName=DNS:$host -keyalg ${KEYALG} -keysize ${KEYSIZE} -sigalg ${SIGALG} -validity ${DAYS} -keystore ${host}.keystore.jks -dname "${dname}" -keypass ${STORE_PASSWORD} -storepass ${STORE_PASSWORD}
  if [ "$?" == "1" ]; then
    genkeypairError
  fi

  STEP=$(($STEP + 1))

  echo -e "\e[00;31m$STEP. Generate a signing request for ${host} using -sigalg ${SIGALG}\e[00m"
  verbose keytool -certreq -keystore ${host}.keystore.jks -storepass ${STORE_PASSWORD} -alias ${host} -sigalg ${SIGALG} -file ${host}.csr
  STEP=$(($STEP + 1))

  echo -e "\e[00;31m$STEP. and sign with our CA using ${SIGALG}\e[00m"
  verbose keytool -gencert -infile ${host}.csr -outfile ${host}.cer -ext SubjectAlternativeName=DNS:$host -keystore ${CA_ALIAS}.jks -storepass ${STORE_PASSWORD} -keypass ${STORE_PASSWORD} -validity ${DAYS} -alias ${CA_ALIAS} -sigalg ${SIGALG}
  STEP=$(($STEP + 1))
  # note: specifying an invalid alias will give a NullPointerException without any explanation!
 
  echo -e "\e[00;31m$STEP. Import the CA so a chain can be established \e[00m"
  verbose keytool -importcert -keystore ${host}.keystore.jks -storepass ${STORE_PASSWORD} -keypass ${STORE_PASSWORD} -trustcacerts -alias ${CA_ALIAS} -file ${CA_ALIAS}.cer -noprompt
  STEP=$(($STEP + 1))

  echo -e "\e[00;31m$STEP. Import the signed certificate for $host \e[00m"
  verbose keytool -importcert -keystore ${host}.keystore.jks -storepass ${STORE_PASSWORD} -keypass ${STORE_PASSWORD} -alias ${host} -file ${host}.cer -noprompt
  STEP=$(($STEP + 1))

  convertToP12 ${host}

  # we no longer need the signing request
  rm ${host}.csr
}

##########################################################################################################
# Convert a JKS keystore to a PKCS12
##########################################################################################################
function convertToP12()
{
  local host=$1
  
  echo -e "\e[00;31m$STEP. Converting JKS to PKCS12\e[00m"
  verbose keytool -importkeystore -srckeystore ${host}.keystore.jks -srcalias "${host}" -destkeystore "${host}.p12" -srcstoretype jks -deststoretype pkcs12 -srcstorepass ${STORE_PASSWORD} -deststorepass ${STORE_PASSWORD}
  STEP=$(($STEP + 1))
}

##########################################################################################################
# Export the private keys and do some convertions. They will be needed to for Apache configuration
# keytool refuses to export the private key, so we use the PKCS12 keystore
##########################################################################################################
function prepareCertsForApache()
{
  local host=$1

  echo -e "\e[00;31m$STEP. Extract the private key from the PKCS12 keystore and create the pem formatted file\e[00m"
  verbose openssl pkcs12 -in ${host}.p12 -passin pass:${STORE_PASSWORD} -nocerts -nodes -out ${host}.encrypted_key.pem
  STEP=$(($STEP + 1))

  echo -e "\e[00;31m$STEP. Decrypting key as mod_proxy cannot deal with encrypted keys\e[00m"
  verbose openssl rsa -in ${host}.encrypted_key.pem -out ${host}.key.pem
  STEP=$(($STEP + 1))

  echo -e "\e[00;31m$STEP. convert the host cert to pem format\e[00m"
  verbose openssl x509 -inform der -in ${host}.cer -outform pem -out ${host}.pem
  STEP=$(($STEP + 1))
 
  echo -e "\e[00;31m$STEP. Combine the server (unencrypted) key and the client cert into a single pem file for use with SSLProxyMachineCertificateFile\e[00m"
  verbose cat ${host}.pem ${host}.key.pem >${host}.cert+key.pem
  STEP=$(($STEP + 1))
}

##########################################################################################################
# write out a mod_cluster configuration for Apache
##########################################################################################################
function generateModClusterConfig()
{
  local host=$1
  local MP="mod_cluster_${host}.conf"

  echo "# mod_cluster.conf configuration for 2 way SSL connections to JBoss" >$MP
  echo "" >>$MP
  echo "# These modules are often already loaded in httpd.conf." >>$MP
  echo "# Loading them twice is harmless but will generate warnings. Remove as needed" >>$MP
  echo "LoadModule proxy_module modules/mod_proxy.so" >>$MP
  echo "LoadModule proxy_ftp_module modules/mod_proxy_ftp.so" >>$MP
  echo "LoadModule proxy_http_module modules/mod_proxy_http.so" >>$MP
  echo "LoadModule proxy_ajp_module modules/mod_proxy_ajp.so" >>$MP
  echo "LoadModule proxy_connect_module modules/mod_proxy_connect.so" >>$MP
  echo "LoadModule ssl_module modules/mod_ssl.so" >>$MP
  echo "" >>$MP
  echo "# These are specific for mod_cluster" >>$MP
  echo "LoadModule slotmem_module modules/mod_slotmem.so" >>$MP
  echo "LoadModule manager_module modules/mod_manager.so" >>$MP
  echo "LoadModule proxy_cluster_module modules/mod_proxy_cluster.so" >>$MP
  echo "LoadModule advertise_module modules/mod_advertise.so" >>$MP
  echo "" >>$MP
  echo "Listen $host:$MOD_CLUSTER_PORT" >>$MP
  echo "" >>$MP
  echo "# Without these parameters, mod_cluster behaves erratically." >>$MP
  echo "SetEnv proxy-nokeepalive 1" >>$MP
  echo "SetEnv proxy-initial-not-pooled 1" >>$MP
  echo "" >>$MP
  echo "# IMPORTANT: set the security as required !" >>$MP
  echo "<VirtualHost $host:$MOD_CLUSTER_PORT>" >>$MP
  echo "  <Directory />" >>$MP
  echo "    Order deny,allow" >>$MP
  echo "    Deny from all" >>$MP
  echo "    Allow from all" >>$MP
  echo "  </Directory>" >>$MP
  echo "" >>$MP
  echo "  SSLEngine on" >>$MP
  echo "  SSLProtocol All -SSLv2 -SSLv3" >>$MP
  echo "  # adjust the ciphers as needed" >>$MP
  echo "  #SSLCipherSuite AES128-SHA:ALL:!ADH:!LOW:!MD5:!SSLV2:!NULL" >>$MP
  echo "  SSLCertificateFile ${APACHE_SSLDIR}/${host}.pem" >>$MP
  echo "  SSLCertificateKeyFile ${APACHE_SSLDIR}/${host}.key.pem" >>$MP
  echo "  SSLCACertificateFile ${APACHE_SSLDIR}/${CA_ALIAS}.pem" >>$MP
  echo "  SSLVerifyClient require" >>$MP
  echo "  SSLOptions +ExportCertData" >>$MP
  echo "  SSLVerifyDepth 10" >>$MP
  echo "" >>$MP
  echo "  EnableMCPMReceive on" >>$MP
  echo "  KeepAliveTimeout 3600" >>$MP
  echo "  MaxKeepAliveRequests 0" >>$MP
  echo "  # the name of the balancer as configured on the JBoss mod cluster subsystem" >>$MP
  echo "  ManagerBalancerName ${MOD_CLUSTER_BALANCER}" >>$MP
  if [ "${MOD_CLUSTER_ADVERTIZE}" == "true" ]; then
    echo "  ServerAdvertise On" >>$MP
  else
    echo "  # Do not use advertising. JBoss will be configured with a list of the Apache hosts" >>$MP
    echo "  ServerAdvertise Off" >>$MP
  fi
  echo "</VirtualHost>" >>$MP
  echo "" >>$MP
  echo "SSLProxyEngine On" >>$MP
  echo "SSLProxyVerify require" >>$MP
  echo "SSLProxyCACertificateFile ${APACHE_SSLDIR}/${CA_ALIAS}.pem" >>$MP
  echo "SSLProxyMachineCertificateFile ${APACHE_SSLDIR}/${host}.cert+key.pem" >>$MP
  echo "SSLProxyProtocol ALL -SSLv2 -SSLv3" >>$MP
  echo "" >>$MP
  echo "# added based on https://issues.jboss.org/browse/MODCLUSTER-250  and   http://seamspace.blogspot.fr/2011/09/clustering-with-jboss-modcluster-and-as.html" >>$MP
  echo "ProxyPreserveHost On" >>$MP
  echo "" >>$MP
  echo "# IMPORTANT: set the security as required !" >>$MP
  echo "<Location /mod_cluster-manager>" >>$MP
  echo "    SetHandler mod_cluster-manager" >>$MP
  echo "    Order deny,allow" >>$MP
  echo "    Deny from all" >>$MP
  echo "    Allow from all" >>$MP
  echo "</Location>" >>$MP  
}

##########################################################################################################
# write out a mod_proxy configuration for Apache
##########################################################################################################
function generateModProxyConfig()
{
  local apache=$1
  local jbosshost=$2
  local MP="mod_proxy_${apache}.conf"
  
  echo "# no forward proxy, we'll use reverse proxy" >>$MP
  echo "ProxyRequests off" >>$MP
  echo "" >>$MP
  echo "SSLProxyEngine On" >>$MP
  echo "" >>$MP
  echo "# the remote JBoss server *must* send a server cert" >>$MP
  echo "SSLProxyVerify require" >>$MP
  echo "" >>$MP
  echo "# File of concatenated PEM-encoded CA Certificates for Remote Server Auth: so the CA which signed the JBoss server cert" >>$MP
  echo "SSLProxyCACertificateFile ${APACHE_SSLDIR}/${CA_ALIAS}.pem" >>$MP
  echo "" >>$MP
  echo "# File of concatenated PEM-encoded client certificates and keys to be used by the proxy" >>$MP
  echo "SSLProxyMachineCertificateFile ${APACHE_SSLDIR}/${apache}.cert+key.pem" >>$MP
  echo "" >>$MP
  echo "# example configuration for a single context" >>$MP
  echo "ProxyPass /jmx-console https://${jbosshost}:8443/jmx-console" >>$MP
  echo "ProxyPassReverse /jmx-console  https://${jbosshost}:8443/jmx-console" >>$MP
  echo "" >>$MP
  echo "# IMPORTANT: set the security as required !" >>$MP
  echo "<Proxy *>" >>$MP
  echo "Order deny,allow" >>$MP
  echo "    Allow from all" >>$MP
  echo "</Proxy>" >>$MP
}

##########################################################################################################
# generate the ssl.conf for Apache
##########################################################################################################
function generateSSLConfig()
{
  local host=$1
  local MP="ssl_${host}.partial_conf"

  echo "# This is NOT a complete ssl.conf file. This only contains the lines you need to" >>$MP
  echo "# configure in the existing conf.d/ssl.conf file">>$MP
  echo " " >>$MP
  echo "SSLCertificateFile ${APACHE_SSLDIR}/${host}.pem" >>$MP
  echo "SSLCertificateKeyFile ${APACHE_SSLDIR}/${host}.key.pem" >>$MP
  echo "SSLCACertificateFile ${APACHE_SSLDIR}/${CA_ALIAS}.pem" >>$MP
  echo "SSLVerifyClient require" >>$MP
  echo "SSLOptions +ExportCertData" >>$MP
  echo "SSLVerifyDepth  10" >>$MP
  echo "SSLProtocol All -SSLv2 -SSLv3" >>$MP
  echo "# adjust the ciphers as needed" >>$MP
  echo "#SSLCipherSuite AES128-SHA:ALL:!ADH:!LOW:!MD5:!SSLV2:!NULL" >>$MP
}

##########################################################################################################
# write out a CLI script to add the mod_cluster subsystem and add the HTTPS connector
##########################################################################################################

function createCLIforModclusterSubsystem()
{
  local jbosshost=$1
  local apache=$2
  
  local MP="web_modcluster.cli"
  
  echo "# This script assumes the mod_cluster subsystem is absent." >$MP
  echo "/extension=org.jboss.as.modcluster:add()"  >>$MP
  echo "batch" >>$MP
  echo "${PROFILE_PREFIX}/subsystem=web/connector=https:add(secure=true,name=https,socket-binding=https,scheme=https,protocol=\"HTTP/1.1\")" >>$MP
  echo "${PROFILE_PREFIX}/subsystem=web/connector=https/ssl=configuration:add(name=ssl,password=${STORE_PASSWORD},certificate-key-file=\"${JBOSS_CONFDIR}/${jbosshost}.keystore.jks\",key-alias=\"${jbosshost}\",ca-certificate-file=\"${JBOSS_CONFDIR}/truststore.jks\",verify-client=true,protocol=\"TLSv1,TLSv1.1,TLSv1.2\")" >>$MP

  echo "${PROFILE_PREFIX}/subsystem=modcluster:add()" >>$MP
  if [ "${MOD_CLUSTER_ADVERTIZE}" == "true" ]; then
    echo "# with advertizing" >>$MP
    echo "#${PROFILE_PREFIX}/subsystem=modcluster/mod-cluster-config=configuration:add(connector=\"${MOD_CLUSTER_CONNECTOR}\",advertise-socket=modcluster)" >>$MP
  else
    echo "# fixed proxy list" >>$MP
    echo "${PROFILE_PREFIX}/subsystem=modcluster/mod-cluster-config=configuration:add(connector=\"${MOD_CLUSTER_CONNECTOR}\",advertise=false,balancer=\"${MOD_CLUSTER_BALANCER}\",proxy-list=\"${apache}:${MOD_CLUSTER_PORT}\")" >>$MP
  fi
  echo "" >>$MP
  echo "${PROFILE_PREFIX}/subsystem=modcluster/mod-cluster-config=configuration/dynamic-load-provider=configuration:add()" >>$MP
  echo "${PROFILE_PREFIX}/subsystem=modcluster/mod-cluster-config=configuration/dynamic-load-provider=configuration/load-metric=configuration:add(type=busyness)" >>$MP
  echo "${PROFILE_PREFIX}/subsystem=modcluster/mod-cluster-config=configuration/ssl=configuration:add(key-alias=${jbosshost},certificate-key-file=\"${JBOSS_CONFDIR}/${jbosshost}.keystore.jks\",password=${STORE_PASSWORD},ca-certificate-file=\"${JBOSS_CONFDIR}/truststore.jks\", protocol=\"TLSv1,TLSv1.1,TLSv1.2\")" >>$MP
  echo "run-batch" >>$MP
}

#####################  Main ########################
checkArguments "$@"

echo "This could take some time. Please be patient..."

createOrFindCA "${CA_ALIAS}" "${CA_DN}"

# there is no real difference between host 1 and 2, just for convience you can specify two of them in one go. Same is true for the browser certificate.
if [ -n "${HOST1}" ]; then
  generateHost "${HOST1}" "${HOST1_DN}"
fi

if [ -n "${HOST2}" ]; then
  generateHost "${HOST2}" "${HOST2_DN}"
fi

if [ -n "${BROWSER}" ]; then
  generateHost "${BROWSER}" "${BROWSER_DN}"
fi

if [ "${GENERATE_MOD_FILES}" == "true" ]; then
  # the server does not really need the p12 files
  # prepareCertsForApache "${HOST1}"

  prepareCertsForApache "${HOST2}"
  createCLIforModclusterSubsystem "${HOST1}" "${HOST2}"
  generateModClusterConfig "${HOST2}"
  generateModProxyConfig "${HOST2}" "${HOST1}"
  generateSSLConfig "${HOST2}"
fi

echo
echo "==================================================================================="
echo -e "                             \e[00;31mDONE\e[00m"
echo "==================================================================================="
if [ "${CA_WAS_GENERATED}" == "true" ]; then
  echo "truststore.jks"
  keytool -list -keystore truststore.jks -storepass ${STORE_PASSWORD}
  echo "==================================================================================="
  echo "CA certificate  : ${CA_ALIAS}.cer"
  echo "                  ${CA_ALIAS}.pem"
  echo "CA keystore     : ${CA_ALIAS}.jks"
  echo "                  ${CA_ALIAS}.p12"
  echo " "
  echo "Not all of these CA files are needed, it is just convienent to have them"
  echo "==================================================================================="
fi
if [ -n "${HOST1}" ]; then
  echo "${HOST1}.keystore.jks"
  keytool -list -keystore ${HOST1}.keystore.jks -storepass ${STORE_PASSWORD}
  echo "==================================================================================="
fi
if [ -n "${HOST2}" ]; then
  echo "${HOST2}.keystore.jks"
  keytool -list -keystore ${HOST2}.keystore.jks -storepass ${STORE_PASSWORD}
  echo "==================================================================================="
fi
if [ -n "${BROWSER}" ]; then
  echo "${BROWSER}.p12"
  keytool -list -keystore ${BROWSER}.p12 -storepass ${STORE_PASSWORD} -storetype pkcs12
  echo "==================================================================================="
  echo "Import ${CA_ALIAS}.cer (as an authority)"
  echo "and ${BROWSER}.p12 (personal cert) in your browser"
  echo "==================================================================================="
fi
if [ "${GENERATE_MOD_FILES}" == "true" ]; then
  echo "JBoss:"
  echo " web_modcluster.cli"
  echo "   use with jboss-cli.sh to setup the modcluster subsystem and a HTTPS connector"
  echo ""
  echo " Copy these files to the jboss configuration directory"
  echo "   ${HOST1}.keystore.jks"
  echo "   truststore.jks"
  echo "==================================================================================="
  echo "Apache:"
  echo "Copy the following files to /etc/httpd/conf.d  You might need to tweak the file"
  echo "   mod_cluster.conf"
  echo " OR"
  echo "   mod_proxy.conf"
  echo ""
  echo "Copy the following files to /etc/httpd/${APACHE_SSLDIR}"
  echo "   ${HOST2}.pem"
  echo "   ${HOST2}.key.pem"
  echo "   ${CA_ALIAS}.pem"
  echo "The file \"ssl_${HOST2}.partial_conf\" contains the SSL"
  echo "directives that should be set in /etc/httpd/conf.d/ssl.conf"
  echo "==================================================================================="
fi
ls -l
