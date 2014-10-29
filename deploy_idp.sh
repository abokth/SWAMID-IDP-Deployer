#!/bin/bash
# UTF-8
HELP="
##############################################################################
# Shibboleth deployment script by Anders Lördal                              #
# Högskolan i Gävle and SWAMID                                               #
#                                                                            #
# Version 2.0                                                                #
#                                                                            #
# Deploys a working IDP for SWAMID on an Ubuntu system                       #
# Uses: jboss-as-distribution-6.1.0.Final or tomcat6                         #
#       shibboleth-identityprovider-2.4.0                                    #
#       cas-client-3.2.1-release                                             #
#                                                                            #
# Templates are provided for CAS and LDAP authentication                     #
#                                                                            #
# To disable the menu based interface, run with argument '-c'.               #
# To install without confirmation, run with argument '-d'                    #
#    NOTE! some of theese files WILL contain cleartext passwords.            #
#                                                                            #
# To add a new template for another authentication, just add a new directory #
# under the 'prep' directory, add the neccesary .diff files and add any      #
# special handling of those files to the script.                             #
#                                                                            #
# You can pre-set configuration values in the file 'config'                  #
#                                                                            #
# Please send questions and improvements to: anders.lordal@hig.se            #
##############################################################################
"

# Copyright 2011, 2012, 2013 Anders Lördal, Högskolan i Gävle and SWAMID
# Copyright 2013 Alexander Boström, Kungliga Tekniska högskolan
#
# This file is part of IDP-Deployer
#
# IDP-Deployer is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# IDP-Deployer is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IDP-Deployer.  If not, see <http://www.gnu.org/licenses/>.

set -e
set -o pipefail

umask 022

declare -a tmpfiles
cleanup() {
	rm -rf "${tmpfiles[@]}"
}

errx() {
	trap - EXIT
	cleanup
	echo >&2 "$@"
	restore_bup
	exit 1
}

cdpush() { pushd >/dev/null "$@"; }
cdpop() { popd >/dev/null; }

restore_bup() {
	if [[ -n "$bupFile" && -e "$bupFile" ]]; then
		if [[ -e "$installdir" ]]; then
			mv "$installdir" "$installdir".failed.$ts
		fi
		echo "Restoring the original $installdir ..."
		tar zxf "${bupFile}" -C "$(dirname "$installdir")"
		rm "$bupFile"
	fi
}

onexit() {
	local -i exitcode=$?
	local l="${BASH_LINENO}"
	#local cmd="$BASH_COMMAND"
	trap - EXIT
	cleanup
	if (( $exitcode == 0 )); then exit 0; fi
	restore_bup
	#echo >&2 "$0": command '"'"$cmd"'"' failed with code "$exitcode"
	echo >&2 "$0": command at line $l failed with code "$exitcode"
	exit $exitcode
}
trap onexit EXIT

mdSignerFinger="12:60:D7:09:6A:D9:C1:43:AD:31:88:14:3C:A8:C4:B7:33:8A:4F:CB"

# Default enable of whiptail UI
GUIen=y
# Version of shibboleth IDP
shibVer="2.4.0"

installdir=/opt/local/shibboleth-idp
if [[ -e /opt/shibboleth-idp ]]; then installdir=/opt/shibboleth-idp; fi
builddir=/opt/local/shibboleth-deps
downloaddir=/opt/local/dist

# Default values
Spath="$(cd "$(dirname "$0")" && pwd)"
ts=$(date "+%s")

FQDN="$(hostname).localdomain"
ipaddrs=$(ip addr show scope global | sed -nre 's,^ +inet[^ ]* ([^ /]+)(|/[^ ]+) .*$,\1,p;')
v4addr=$(dig +short $(hostname) IN A) || :
v6addr=$(dig +short $(hostname) IN AAAA) || :
for addr in $v4addr $v6addr $ipaddrs; do
	if name=$(dig +short -x $addr) && [[ -n "$name" ]]; then
		nodot="${name%.}"
		if host $nodot >/dev/null 2>&1; then
			FQDN="$nodot"
			Dname=$(cut -d. -f2- <<<"$nodot")
			break
		fi
	fi
done

fetchurl() {
	local file="$downloaddir/$1"; shift
	local url="$1"; shift

	if [[ -s "$file" ]]; then
		return 0
	fi

	tmpfiles[${#tmpfiles[@]}]="$file.new$$"
	curl --output "$file.new$$" "$url"
	mv "$file.new$$" "$file"
}

genpw() {
	local -i d=$((RANDOM % 10 + 10)) c=$((RANDOM % 20 + 10)) uc=$((RANDOM % 20 + 10)) s=0
	local -i l=$((RANDOM % 20 + 10 + d + c + uc + s))
	pw=$(mkpasswd -l $l -d $d -c $c -C $uc -s $s)
}

backup_file() {
	local file="$1"; shift
	local suffix="$1"; shift

	if [[ -e "$file" && ! -e "$file$suffix" ]]; then
		cp "$file" "$file$suffix"
	fi
}

mktmp() {
    local tmpvar="$1"; shift
    local newtmpfile=$(mktemp "$@")
    tmpfiles[${#tmpfiles[@]}]="$newtmpfile"
    eval "$tmpvar='$newtmpfile'"
}

quiet() {
	mktmp outtmp
	if ! "$@" >"$outtmp" 2>&1; then
		cat "$outtmp" >&2
		errx "Command failed:" "$@"
	fi
}

{ type -t whiptail >/dev/null && stty >/dev/null 2>&1; } || GUIen="n"
if [[ "$GUIen" == "y" ]]; then
	read termrows termcols <<<$(stty size)
	whipSize="$(($termrows - 3)) $((termcols - 3))"
fi

# parse options
options=$(getopt -o cdh -l "help" -- "$@")
eval set -- "${options}"
while [[ $# -gt 0 ]]; do
	case "$1" in
		-c)
			GUIen="n"
		;;
		-d)
			saveconfig="y"
			doinstall="y"
		;;
		-h | --help)
			printf "%s\n" "${HELP}"
			exit
		;;
	esac
	shift
done

# guess package manager
if type -t apt-get >/dev/null; then
	pkgmanager="apt"
elif type -t yum >/dev/null; then
	pkgmanager="yum"
else
	errx "Unknown package manager."
fi

# read config file
if [[ -f "${Spath}/config" ]]; then
	. ${Spath}/config
fi

# check for installed IDP
upgrade=0
if [[ -d "$installdir" ]]; then
	upgrade=1
fi

whiptail_value() {
    if [[ -z "$whiptailtmp" ]]; then
	mktmp whiptailtmp
    fi
    whiptail --output-fd=10 10>"$whiptailtmp" "$@"
    value=$(cat "$whiptailtmp")
}

text_input() {
	local variable="$1"; shift
	local title="$1"; shift
	local prompt="$1"; shift
	local default="$1"; shift
	local value

	while eval [[ -z "\${$variable}" ]]; do
		if [[ "${GUIen}" = "y" ]]; then
			whiptail_value --backtitle "SWAMID IDP Deployer" --title "$title" --nocancel --inputbox --clear -- "$prompt" ${whipSize} "$default"
		else
			echo "### $title ###"
			echo -e "$prompt [$default] "
			read value
			if [[ -z "$value" ]]; then
				value="$default"
			fi
			echo ""
		fi
		eval "$variable='$value'"
	done
}

menu_input() {
	local variable="$1"; shift
	local title="$1"; shift
	local prompt="$1"; shift
	local value
	local p
	local -i odd=0

	if eval [[ -z "\${$variable}" ]]; then
		if [[ "${GUIen}" = "y" ]]; then
			whiptail_value --backtitle "SWAMID IDP Deployer" --title "$title" --nocancel --clear --menu "$prompt" ${whipSize} "$@" || :
		else
			echo "### $title ###"
			echo -e "$prompt"
			for p in "$@"; do
				if (( $odd )); then
					echo "$p"
				else
					echo -n "$p "
				fi
				odd=$((1-$odd))
			done
			read value
			[[ -n "$value" ]]
			echo ""
		fi
		eval "$variable='$value'"
	fi
}

yesno_input() {
	local variable="$1"; shift
	local title="$1"; shift
	local prompt="$1"; shift
	local defaultno="$1"; shift
	local defval="$1"; shift
	local defprompt="$1"; shift
	local value

	if eval [[ -z "\${$variable}" ]]; then
		if [[ "${GUIen}" = "y" ]]; then
			value="y"
			whiptail --backtitle "SWAMID IDP Deployer" --title "$title" --yesno --clear $defaultno -- "$prompt" ${whipSize} || value="n"
		else
			echo "### $title ###"
			echo -e "$prompt $defprompt"
			read value
			if [[ -z "$value" ]]; then value=$defval; echo $defval; fi
			echo ""
		fi
		eval "$variable='$value'"
	fi
}

defaultyes_input() {
	local variable="$1"; shift
	local title="$1"; shift
	local prompt="$1"; shift
	yesno_input "$variable" "$title" "$prompt" "" "y" "Y/n"
}

defaultno_input() {
	local variable="$1"; shift
	local title="$1"; shift
	local prompt="$1"; shift
	yesno_input "$variable" "$title" "$prompt" "--defaultno" "n" "y/N"
}

defaultyes_input fticks "Send anonymous data" "Do you want to send anonymous usage data to SWAMID?"
defaultyes_input targetedid "eduPersonTargetedID" "Do you want to install support for eduPersonTargetedID?"
defaultyes_input uapprove "uApprove" "Do you want to install support for uApprove?"
defaultno_input google "Attributes to Google" "Do you want to release attributes to Google?"

text_input schachomeorganization "Domain name (schacHomeOrganization)" "Please input your main domain name (schacHomeOrganization) (xxx.yy)" "${Dname}"
persistentid_salt_file="/root/shibboleth-persistentid-salt-$schachomeorganization"
fticks_key_file=/root/fticks-key-backup-$schachomeorganization

text_input scope "Attribute value scope" "Please input the scope for attribute values (xxx.yy)" "$schachomeorganization"

if [[ "$targetedid" == "y" ]]; then
	if [[ -e "$persistentid_salt_file" ]]; then
		esalt=$(cat "$persistentid_salt_file")
	fi
	if [[ -z "$esalt" && -e "$installdir"/conf/attribute-resolver.properties ]]; then
		esalt=$(native2ascii -reverse <"$installdir"/conf/attribute-resolver.properties | sed -nre 's,^targetedid\.salt *= *,,p;')
		echo "$esalt" >"$persistentid_salt_file"
	fi
fi

if [[ "$fticks" == "y" ]]; then
	if [[ -e "$installdir"/conf/fticks-key.txt || -e "$fticks_key_file" ]]; then
		have_fticks_key=yes
	fi
fi

while [[ "$targetedid" == "y" && -z "$esalt" && "$newdomain" != "new" ]] || [[ "$fticks" == "y" && -z "$have_fticks_key" && "$newdomain" != "new" ]]; do
	menu_input newdomain "New domain" "Is this a new domain? (Generate new persistent ID and FTICKS keys?)" 3 "." "" new "This is a new domain" moved "This domain is being/has been served by another server."
	if [[ "$newdomain" == "." ]]; then newdomain=""; fi

	if [[ "$targetedid" == "y" && -z "$esalt" && "$newdomain" == "moved" ]]; then
		text_input esalt "Targeted ID/EPTID salt" "Please input the old Targeted ID/EPTID salt for this domain. (Look in $persistentid_salt_file and $installdir/conf/attribute-resolver.properties on your old server.)" ""
	fi

	if [[ "$fticks" == "y" && -z "$have_fticks_key" && "$newdomain" == "moved" ]]; then
		text_input ftickskey "FTICKS key" "Please input the old FTICKS key for this domain. (Look in $fticks_key_file and $installdir/conf/fticks-key.txt on your old server.)" ""
		if [[ -n "$ftickskey" ]]; then
			have_fticks_key=yes
			echo "$ftickskey" >"$fticks_key_file"
		fi
	fi
done

if [[ "${google}" == "y" ]]; then
	text_input googleDom "Your Google domain name" "Please input your Google services domain name" "student.$schachomeorganization"
fi

menu_input appserv "Application server" "Which application server do you want to use?" 2 tomcat "Apache Tomcat 6" jboss "Jboss Application server 6"

if [[ "$appserv" == "tomcat" ]]; then
	defaultyes_input apachefrontend "Apache as AJP frontend" "Do you want to use Apache httpd as a web frontend (mod_ajp)?"
	appservconf="$appserv"
	if [[ "$apachefrontend" == "y" ]]; then appservconf="$appserv.ajp"; fi
fi

menu_input type "Authentication type" "Which authentication method do you want to use?" 2 cas "Central Authentication Service" ldap "Username/Password Authentication with LDAP"
prep="prep/${type}"

text_input ldapserver "LDAP server" "Please input your LDAP server names (ldap.xxx.yy).\n\nSeparate multiple servers with spaces.\SSL (LDAPS) will be required." "ldap.${Dname}"

ldapurls=$(for s in $ldapserver; do echo "ldaps://$s"; done|tr '\n' ' '|sed 's, $,,;')

text_input ldapbasedn "LDAP base DN" "Please input your LDAP base DN" $(sed <<<"$schachomeorganization" -re 's:^:dc=:g; s:\.:,dc=:g;')
text_input ldapbinddn "LDAP bind DN" "Please input your LDAP bind DN" "uid=shibbolethserver,ou=Special Users,$ldapbasedn"
if [[ -e "$installdir"/conf/attribute-resolver.properties ]]; then
	ldappass=$(native2ascii -reverse <"$installdir"/conf/attribute-resolver.properties | sed -nre 's,^myldap\.password *= *,,p;')
fi
defaultyes_input subsearch "LDAP Subsearch" "Do you want to enable LDAP subtree search?"
text_input ninc "LDAP norEduPersonNIN source attribute" "Please specify the LDAP sourc attribute for the norEduPersonNIN value (Should have the format YYYYMMDDnnnn)" "norEduPersonNIN"

text_input idpurl "IDP URL" "Please input the URL to reach this IDP" "https://${FQDN}"
idpurl="${idpurl%/}"

defentityid=$(sed <<<"${idpurl}/idp/shibboleth" -re 's,-[0-9]+\.,.,; s,[0-9]+\.,.,;')
text_input entityid "IDP URL" "Please input the entityID for this IDP" "$defentityid"

t="${idpurl#*://}"
idphostname="${t%/*}"

if [[ "${type}" = "cas" ]]; then
	text_input casurl "CAS URL" "Please input the URL for your CAS server" "https://cas.${Dname}/cas"
	text_input caslogurl "CAS URL" "Please input the login URL for your CAS server" "${casurl}/login"
fi

text_input certOrg "Organization" "Please input organisation name (long format) for metadata (\"University of Oz\")" ""
cctry=$(tr '[[:lower:]]' '[[:upper:]]' <<<"${FQDN##*.}")
if [[ "$cctry" == ?? ]]; then
	ccdef="$cctry"
fi
text_input certC "Organization" "Please input country code for metadata (SE)" "$ccdef"
if [[ "$certC" == "SE" ]]; then
	certLongC="Sweden"
fi
text_input certLongC "Organization" "Please input country name for metadata (Sweden)" ""
acro=$(sed -re 's,([^ ])[^ ]*( |$),\1,g;' <<<"${certOrg}" | tr '[[:lower:]]' '[[:upper:]]')
text_input certAcro "Organisation acronym" "Please input organisation Acronym (eg. 'HiG')" "$acro"

if [[ "$uapprove" == "y" ]]; then
	text_input uapprove_db_host "uApprove PostgreSQL DB host" "Please input the hostname of the uApprove DB" localhost.localdomain
	text_input uapprove_db_name "uApprove PostgreSQL DB name" "Please input the name of the uApprove DB" "uapprove_$(hostname -s|tr '-' '_')"
	text_input uapprove_db_user "uApprove PostgreSQL DB user" "Please input the name of the uApprove DB user" "$uapprove_db_name"
fi

if [[ "$targetedid" == "y" ]]; then
	default=localhost.localdomain
	if [[ -n "$uapprove_db_host" ]]; then default="$uapprove_db_host"; fi
	text_input targetedid_db_host "targetedid PostgreSQL DB host" "Please input the hostname of the targetedid DB" $default
	text_input targetedid_db_name "targetedid PostgreSQL DB name" "Please input the name of the targetedid DB" "targetedid_$(hostname -s|tr '-' '_')"
	text_input targetedid_db_user "targetedid PostgreSQL DB user" "Please input the name of the targetedid DB user" "$targetedid_db_name"
fi

mktmp confirmtext
cat > "$confirmtext" << EOM
Options passed to the installer:


Application server:        ${appserv}
Apache httpd front end:    ${apachefrontend}
Authentication type:       ${type}

Release to Google:         ${google}
Google domain name:        ${googleDom}

LDAP server:               ${ldapserver}
LDAP Base DN:              ${ldapbasedn}
LDAP Bind DN:              ${ldapbinddn}
LDAP Subsearch:            ${subsearch}
norEduPersonNIN:           ${ninc}

IDP EntityID:              ${entityid}
IDP URL:                   ${idpurl}
CAS Login URL:             ${caslogurl}
CAS URL:                   ${casurl}

Org. domain name:          ${schachomeorganization}
Attribute valaue scope:    ${scope}
Cert org string:           ${certOrg}
Cert country string:       ${certC}
norEduOrgAcronym:          ${certAcro}
Country descriptor:        ${certLongC}

EPTID support:             ${targetedid} $targetedid_db_host $targetedid_db_name $targetedid_db_user
uApprove support:          ${uapprove} $uapprove_db_host $uapprove_db_name $uapprove_db_user

Usage data to SWAMID:      ${fticks}

Logos:                     ${pnglogo}
                           ${pngmobilelogo}
                           ${pngfederationlogo}

Extra filter tokens:       ${extra_filter_tokens}
EOM

if [[ "${GUIen}" = "y" && "$doinstall" != "y" ]]; then
	whiptail --backtitle "SWAMID IDP Deployer" --title "Confirm" --scrolltext --clear --textbox "$confirmtext" ${whipSize}
else
	cat "$confirmtext"
fi

cat >"${Spath}/config.tmp" << EOM
appserv="$appserv"
apachefrontend="$apachefrontend"
type="$type"
google="$google"
googleDom="$googleDom"
ldapserver="$ldapserver"
ldapbasedn="$ldapbasedn"
ldapbinddn="$ldapbinddn"
subsearch="$subsearch"
entityid="$entityid"
idpurl="$idpurl"
caslogurl="$caslogurl"
casurl="$casurl"
certOrg="$certOrg"
certC="$certC"
schachomeorganization="$schachomeorganization"
scope="$scope"
fticks="$fticks"
targetedid="$targetedid"
targetedid_db_host="$targetedid_db_host"
targetedid_db_name="$targetedid_db_name"
targetedid_db_user="$targetedid_db_user"
ninc="$ninc"
certAcro="$certAcro"
certLongC="$certLongC"
uapprove="$uapprove"
uapprove_db_host="$uapprove_db_host"
uapprove_db_name="$uapprove_db_name"
uapprove_db_user="$uapprove_db_user"
pnglogo="$pnglogo"
pngmobilelogo="$pngmobilelogo"
pngfederationlogo="$pngfederationlogo"
extra_filter_tokens="$extra_filter_tokens"
EOM
tmpfiles[${#tmpfiles[@]}]="${Spath}/config.tmp"

if [[ -e "${Spath}/config" ]] && cmp -s "${Spath}/config"{,.tmp}; then
	: "No configuration changes."
else
	defaultyes_input saveconfig "Save config" "Do you want to save these config values?\n\nIf you save these values the current config file will be overwritten."
	[[ "$saveconfig" == "y" ]]
	mv "${Spath}/config"{.tmp,}
	software_changes=yes
fi

if [[ ! -e "$installdir"/deploy-config ]] || ! cmp -s "${Spath}/config" "$installdir"/deploy-config; then
	software_changes=yes
fi

if [[ -z "$software_changes" ]]; then
	for f in $(find "${Spath}"/files/{webapp,idp}-config -type f); do
		if [[ -e "$f" && "$f" -nt "$installdir"/deploy-config ]]; then
			software_changes=yes
			break
		fi
	done
fi

defaultno_input doinstall "Confirm" "Do you want to install this IDP with these options?"
[[ "$doinstall" == "y" ]]

if [[ "${apachefrontend}" == "n" ]]; then
	for p12 in {/etc/pki/tls,/etc/ssl}/private/localhost.p12; do
		if [[ -e "$p12" ]]; then
			httpsP12="$p12"
			break;
		fi
	done
	if [[ -z "$httpsP12" ]]; then
		errx "First use 'request-cert' to generate a certificate."
	fi
fi

certCN=$(cut <<<"$idpurl" -d/ -f3)

if [[ -e "$installdir"/conf/fticks-key.txt && ! -e "$fticks_key_file" ]]; then
	cp -a "$installdir"/conf/fticks-key.txt "$fticks_key_file"
fi

if [[ "$pkgmanager" == "apt" ]]; then
	apt-get update
	apt-get upgrade || :
	apt-get install patch unzip curl

	if [[ "${fticks}" == "y" ]]; then
		apt-get install git-core maven2 openjdk-6-jdk
	fi

	if [[ "${appserv}" = "tomcat" ]]; then
		apt-get install tomcat6
	fi
	# install java if needed
	if ! type -t java >/dev/null; then
		apt-get install default-jre
	fi
	if ! type -t java >/dev/null; then
		errx "No java could be found! Install a working JRE and re-run this script."
	fi
elif [[ "$pkgmanager" == "yum" ]]; then
	#yum update || :
	rpm -q >/dev/null 2>&1 patch unzip curl || yum install patch unzip curl

	# Look for Java 1.6 or newer. (This excludes GCJ.)
	if ! java -version 2>&1 | egrep -q '^java version "1\.(6|7|8|9|[0-9][0-9]+)'; then
		rpm -q >/dev/null 2>&1 java-1.7.0-openjdk || yum install java-1.7.0-openjdk || :
		if ! java -version 2>&1 | egrep -q '^java version "1\.(6|7|8|9|1[0-9]+)'; then
			errx \
"Java 1.6 or newer required. Install java-1.7.0-openjdk or similar. For
RHEL6, other JVMs are also available in the extra repositories (enable
them i RHN). Check current java version with 'java -version', and if
required, select a suitable version using 'alternatives --config java'."
		fi
	fi

	if [[ "${fticks}" == "y" ]]; then
		# We also need the JDK
		if ! javac -version 2>&1 | egrep -q '^javac 1\.(6|7|8|9|[0-9][0-9]+)'; then
			rpm -q >/dev/null 2>&1 java-1.7.0-openjdk-devel || yum install java-1.7.0-openjdk-devel || :
			if ! javac -version 2>&1 | egrep -q '^javac "1\.(6|7|8|9|1[0-9]+)'; then
				errx \
"Java JDK 1.6 or newer required. Install java-1.7.0-openjdk-devel or similar. For
RHEL6, other JVMs are also available in the extra repositories (enable
them i RHN). Check current JDK version with 'javac -version', and if
required, select a suitable version using 'alternatives --config javac'."
			fi
		fi

		rpm -q >/dev/null 2>&1 git || yum install git
	fi

	if [[ "${appserv}" = "tomcat" ]]; then
		rpm -q >/dev/null 2>&1 tomcat6 || yum install tomcat6
	fi
	
	if [[ "${apachefrontend}" = "y" ]]; then
		rpm -q >/dev/null 2>&1 mod_ssl || yum install mod_ssl
	fi

	if [[ "${uapprove}" == "y" || "${targetedid}" == "y" ]]; then
		if [[ "$uapprove_db_host" == "localhost" || "$uapprove_db_host" == "localhost.localdomain" || "$targetedid_db_host" == "localhost" || "$targetedid_db_host" == "localhost.localdomain" ]]; then
			rpm -q >/dev/null 2>&1 postgresql-server || yum install postgresql-server
		fi
		rpm -q >/dev/null 2>&1 postgresql-jdbc || yum install postgresql-jdbc
		rpm -q >/dev/null 2>&1 postgresql || yum install postgresql
	fi
fi

postgresql_db_create() {
	local db_host="$1"; shift
	local db_name="$1"; shift
	local db_user="$1"; shift
	genpw

	if [[ "$db_host" == "localhost" || "$db_host" == "localhost.localdomain" ]]; then
		postgres_service=$(env LC_ALL=C chkconfig --list|sed -nre 's,^(postgresql.*) .*:on.*$,\1,p;')
		if [[ -z "$postgres_service" ]] || ! service $postgres_service status; then
			echo >&2 "Please set up PostgresSQL on this or another host."
			echo >&2 " service postgresql initdb"
			echo >&2 " chkconfig postgresql on"
			echo >&2 " service postgresql start"
			echo >&2 "Remember to also perform backups."
			errx "No PostgreSQL server configured."
		fi
		/bin/su - postgres <<EOCMD
createuser --no-superuser --no-createdb --no-createrole $db_user
createdb --owner $db_user $db_name
psql -c "ALTER ROLE $db_user WITH PASSWORD '$pw';"
EOCMD
		if ! env PGPASSWORD="$pw" psql --host=$db_host --username=$db_user $db_name -c ''; then
			/bin/su - postgres -c 'echo >>$PGDATA/pg_hba.conf.new ""'
			/bin/su - postgres -c 'echo >>$PGDATA/pg_hba.conf.new "local '"$db_name $db_user"' md5"'
			/bin/su - postgres -c 'echo >>$PGDATA/pg_hba.conf.new "host '"$db_name $db_user"' 127.0.0.1/32 md5"'
			/bin/su - postgres -c 'echo >>$PGDATA/pg_hba.conf.new "host '"$db_name $db_user"' ::1/128 md5"'
			/bin/su - postgres -c 'echo >>$PGDATA/pg_hba.conf.new ""'
			/bin/su - postgres -c 'cat $PGDATA/pg_hba.conf >>$PGDATA/pg_hba.conf.new'
			/bin/su - postgres -c 'mv $PGDATA/pg_hba.conf.new $PGDATA/pg_hba.conf'
			service $postgres_service restart
		fi
	else
		cat <<EOF
###############
/bin/su - postgres <<'EOCMD'
createuser --no-superuser --no-createdb --no-createrole $db_user
createdb --owner $db_user $db_name
psql -c "ALTER ROLE $db_user WITH PASSWORD '$pw';"
EOCMD
/bin/su - postgres -c 'echo >>\$PGDATA/pg_hba.conf ""'
/bin/su - postgres -c 'echo >>\$PGDATA/pg_hba.conf "hostssl $db_name $db_user samenet md5"'
/bin/su - postgres -c 'echo >>\$PGDATA/pg_hba.conf ""'
service postgresql restart
###############

Please copy/paste the above - modified as appropriate for your
environment - to a shell on $db_host. When the database has
been configured, press enter here to continue.

EOF
		read foo
	fi
}

mkdir -p "$builddir"
mktmp opttmp -d "$builddir"/shib-deploy-XXXXXX

mkdir -p "$downloaddir"

fetchurl shibboleth-identityprovider-${shibVer}-bin.zip "http://shibboleth.net/downloads/identity-provider/${shibVer}/shibboleth-identityprovider-${shibVer}-bin.zip"

cd "$opttmp"
if [[ ! -e "$builddir/shibboleth-identityprovider-${shibVer}" ]]; then
	unzip -q "$downloaddir"/shibboleth-identityprovider-${shibVer}-bin.zip
	chmod -R 755 shibboleth-identityprovider-${shibVer}/install.sh
	software_changes=yes
fi

xmlcheck() {
	local l="${BASH_LINENO}"
	local xmlns
	local xmlf xmlbasename
	local jar
	local idpdir

	for idpdir in "$builddir"/shibboleth-identityprovider-${shibVer} "$opttmp"/shibboleth-identityprovider-${shibVer}; do
		if [[ -e "$idpdir" ]]; then
			break
		fi
	done
	if [[ ! -e "$idpdir" ]]; then
		errx "Internal error"
	fi

	if [[ -z "$schemadir" ]]; then
		mktmp schemadir -d
		cdpush "$schemadir"
		for jar in "$idpdir"/lib/*.jar; do
			jar -xf "$jar" schema org/springframework #javax/servlet/resources  org/apache/xml/security/resource/schema
		done
		cat >schema.xsd <<'EOF'
<schema targetNamespace="aggregate" xmlns="http://www.w3.org/2001/XMLSchema" version="1.2">
EOF
		#find org/springframework -name '*.xsd'|sort
		for xmlf in schema/*.xsd org/springframework/beans/factory/xml/*.xsd; do
			xmlbasename=$(basename "$xmlf")
			sed -i "$xmlf" -e 's,classpath:/schema/,,;'
			#sed -i "$xmlf" -e 's,schemaLocation="http://www.ibm.com/webservices/xsd/j2ee_web_services_client_1_1.xsd,schemaLocation="j2ee_web_services_client_1_1.xsd,;'
			if [[ ! -e "$xmlbasename" ]]; then
				ln -s "$xmlf" "$xmlbasename"
				if ! fgrep 'schemaLocation="http' "$xmlf" >/dev/null; then
					xmlns=$(tr '\n' ' ' <"$xmlf" |sed -nre 's,.*<([^ ]+:|)schema [^>]*targetNamespace="([^"]+)".*,\2,p;')
					if [[ -n "$xmlns" ]]; then
						cat >>schema.xsd <<EOF
<import namespace="$xmlns" schemaLocation="$xmlbasename"/>
EOF
					fi
				fi
			fi
		done
		cat >>schema.xsd <<'EOF'
</schema>
EOF
		#cat schema.xsd
		#ls -al
		cdpop
	fi

	if ! xmllint --nonet --xinclude --nowarning --noout --path "$schemadir" --schema "$schemadir"/schema.xsd "$@"; then
		errx "XML syntax failure at line deploy script $l"
	fi
}

filtertokens="$filtertokens s:\\\$IDP_HOME\\\$:$installdir:g;"
filtertokens="$filtertokens s,\\\$IDP_ENTITY_ID\\\$,$entityid,g;"
filtertokens="$filtertokens s:\\\$IDP_SCOPE\\\$:$scope:g;"
filtertokens="$filtertokens s:\\\$IDP_CERTIFICATE\\\$:$installdir/credentials/idp.crt:g;"
filtertokens="$filtertokens s:\\\$IDP_HOSTNAME\\\$:$idphostname:g;"

filtertokens="$filtertokens s,%%%%LDAPURLS%%%%,$ldapurls,g;"
filtertokens="$filtertokens s@%%%%LDAPBASEDN%%%%@$ldapbasedn@g;"
filtertokens="$filtertokens s,%%%%ENTITYID%%%%,$entityid,g;"
filtertokens="$filtertokens s,%%%%IDPURL%%%%,$idpurl,g;"
filtertokens="$filtertokens s,%%%%CASURL%%%%,$casurl,g;"
filtertokens="$filtertokens s,%%%%CASLOGINURL%%%%,$caslogurl,g;"
if [[ "${fticks}" == "y" ]]; then
	filtertokens="$filtertokens s,<!-- %%%%enable_fticks%%%%,<!-- enable_fticks -->,g;"
	filtertokens="$filtertokens s,%%%%enable_fticks%%%% -->,<!-- /enable_fticks -->,g;"
fi
if [[ "${google}" == "y" ]]; then
	filtertokens="$filtertokens s,<!-- %%%%enable_release_to_google%%%%,<!-- enable_release_to_google -->,g;"
	filtertokens="$filtertokens s,%%%%enable_release_to_google%%%% -->,<!-- /enable_release_to_google -->,g;"
fi
if [[ "${type}" == "cas" ]]; then
	filtertokens="$filtertokens s,<!-- %%%%enable_cas%%%%,<!-- enable_cas -->,g;"
	filtertokens="$filtertokens s,%%%%enable_cas%%%% -->,<!-- /enable_cas -->,g;"
elif [[ "${type}" == "ldap" ]]; then
	filtertokens="$filtertokens s,<!-- %%%%enable_ldap%%%%,<!-- enable_ldap -->,g;"
	filtertokens="$filtertokens s,%%%%enable_ldap%%%% -->,<!-- /enable_ldap -->,g;"
fi
if [[ "${uapprove}" == "y" ]]; then
	filtertokens="$filtertokens s,<!-- %%%%enable_uapprove%%%%,<!-- enable_uapprove -->,g;"
	filtertokens="$filtertokens s,%%%%enable_uapprove%%%% -->,<!-- /enable_uapprove -->,g;"
fi
for x_filter_token in $extra_filter_tokens; do
	filtertokens="$filtertokens s,<!-- %%%%${x_filter_token}%%%%,<!-- ${x_filter_token} -->,g;"
	filtertokens="$filtertokens s,%%%%${x_filter_token}%%%% -->,<!-- /${x_filter_token} -->,g;"
done

mktmp idp_config_patch_tmp
cd ${Spath}/files/idp-config/recommended
for f in attribute-filter.xml attribute-resolver.xml handler.xml logging.xml login.config relying-party.xml service.xml; do
	if [[ "${f%.xml}" != "$f" ]] && fgrep xmlns: "../dist/$f" >/dev/null ; then
		xmlcheck "../dist/$f"
		xmlcheck "$f"
	fi
	diff -uw "../dist/$f" "$f" >>"$idp_config_patch_tmp" || :
done

if [[ -e "$installdir"/conf/attribute-resolver.properties ]]; then
	epass=$(native2ascii -reverse <"$installdir"/conf/attribute-resolver.properties | sed -nre 's,^targetedid\.jdbcpassword *= *,,p;')
fi
if [[ -z "$epass" ]]; then
	postgresql_db_create "$targetedid_db_host" "$targetedid_db_name" "$targetedid_db_user"
	env PGPASSWORD="$pw" psql --host=$uapprove_db_host --username=$targetedid_db_user $targetedid_db_name <<'SQL'
CREATE TABLE shibpid (
  localEntity TEXT NOT NULL,
  peerEntity TEXT NOT NULL,
  principalName VARCHAR(255) NOT NULL default '',
  localId VARCHAR(255) NOT NULL,
  persistentId VARCHAR(36) NOT NULL,
  peerProvidedId VARCHAR(255) default NULL,
  creationDate timestamp NOT NULL default CURRENT_TIMESTAMP,
  deactivationDate timestamp NULL default NULL );
CREATE INDEX persistentId ON shibpid (persistentId);
CREATE INDEX persistentId_2 ON shibpid (persistentId, deactivationDate);
CREATE INDEX localEntity ON shibpid (localEntity, peerEntity,localId);
CREATE INDEX localEntity_2 ON shibpid (localEntity, peerEntity, localId, deactivationDate);
CREATE LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION update_creationDate_column()
RETURNS TRIGGER AS $$ BEGIN NEW.creationDate = now(); RETURN NEW; END; $$ language 'plpgsql';
CREATE TRIGGER update_shibpid_creationDate BEFORE UPDATE ON shibpid FOR EACH ROW EXECUTE PROCEDURE update_creationDate_column();
SQL
	epass="$pw"
fi

pass="foo"
if [[ "${upgrade}" -eq 0 ]]; then
	if [[ -z "${pass}" ]]; then
		genpw; pass="$pw"
	fi
	if [[ "$apachefrontend" == "n" && -z "${httpspass}" ]]; then
		genpw; httpspass="$pw"
	fi

	mktmp serverxmltmp
	cat ${Spath}/xml/server.xml.${appservconf} \
		| perl -npe "s#ShIbBKeyPaSs#${pass}#" \
		| perl -npe "s#HtTpSkEyPaSs#${httpspass}#" \
		| perl -npe "s#HtTpSJkS#${httpsP12}#" \
		| perl -npe "s#TrUsTsToRe#${javaCAcerts}#" \
		| perl -npe "s#/opt/shibboleth-idp#$installdir#" \
		> "$serverxmltmp"
	#xmlcheck "$serverxmltmp"
fi

cd "$builddir"
#get depens if needed
if [[ "${appserv}" = "jboss" ]]; then
	if [[ ! -e "$builddir"/jboss-6.1.0.Final ]]; then
		fetchurl jboss-as-distribution-6.1.0.Final.zip http://download.jboss.org/jbossas/6.1/jboss-as-distribution-6.1.0.Final.zip
		cd "$opttmp"
		unzip -q "$downloaddir"/jboss-as-distribution-6.1.0.Final.zip
		chmod 755 jboss-6.1.0.Final

		xmlcheck "$opttmp/jboss-6.1.0.Final"/server/default/conf/login-config.xml
		if [[ "${type}" = "ldap" ]]; then
			cat ${Spath}/${prep}/login-config.xml.diff.template \
				| perl -npe "s#LdApUrI#${ldapurls}#" \
				| perl -npe "s/LdApBaSeDn/${ldapbasedn}/" \
				| perl -npe "s/SuBsEaRcH/${subsearch}/" \
				> ${Spath}/${prep}/login-config.xml.diff
			tmpfiles[${#tmpfiles[@]}]="${Spath}/${prep}/login-config.xml.diff"
			quiet patch "$opttmp/jboss-6.1.0.Final"/server/default/conf/login-config.xml -i ${Spath}/${prep}/login-config.xml.diff
		fi
		xmlcheck "$opttmp/jboss-6.1.0.Final"/server/default/conf/login-config.xml

		ln -s "$installdir"/war/idp.war "$opttmp/jboss-6.1.0.Final"/server/default/deploy/

		cp "$serverxmltmp" "$opttmp/jboss-6.1.0.Final"/server/default/deploy/jbossweb.sar/server.xml
		chmod o-rwx "$opttmp/jboss-6.1.0.Final"/server/default/deploy/jbossweb.sar/server.xml

		mv "$opttmp/jboss-6.1.0.Final" "$builddir"
		if [[ -L "$builddir"/jboss ]]; then
			rm "$builddir"/jboss
		fi
		ln -s "$builddir"/jboss-6.1.0.Final "$builddir"/jboss

		software_changes=yes
	fi
fi

if [[ "${appserv}" = "tomcat" ]]; then
	fetchurl tomcat6-dta-ssl-1.0.0.jar "https://build.shibboleth.net/nexus/content/repositories/releases/edu/internet2/middleware/security/tomcat6/tomcat6-dta-ssl/1.0.0/tomcat6-dta-ssl-1.0.0.jar"
fi

if [[ "${type}" = "cas" ]]; then
	if [[ ! -e "$builddir"/cas-client-3.2.1 ]]; then
		fetchurl cas-client-3.2.1-release.zip "http://downloads.jasig.org/cas-clients/cas-client-3.2.1-release.zip"
		cd "$opttmp"
		unzip -q "$downloaddir"/cas-client-3.2.1-release.zip
		mv cas-client-3.2.1 "$builddir"
		software_changes=yes
	fi
fi

if [[ "${uapprove}" == "y" ]]; then
	if [[ ! -e "$builddir"/uApprove-2.5.0 ]]; then
		fetchurl uApprove-2.5.0.zip https://forge.switch.ch/redmine/attachments/download/1623/uApprove-2.5.0.zip
		cd "$opttmp"
		unzip -q "$downloaddir"/uApprove-2.5.0.zip
		mv uApprove-2.5.0 "$builddir"
		software_changes=yes
	fi
fi

type -t java >/dev/null
if [[ -z "${JAVA_HOME}" ]]; then
	if [[ -e /usr/lib/jvm/jre ]]; then
		# This is whatever 'alternatives --config java' is set to.
		export JAVA_HOME=/usr/lib/jvm/jre
	elif [[ -e /usr/lib/jvm/default-java/jre ]]; then
		# This is whatever 'alternatives --config java' is set to.
		export JAVA_HOME=/usr/lib/jvm/default-java/jre
	else
		# This is suboptimal if the path changes on Java patch releases, don't do this.
		jhome=$(dirname $(dirname $(readlink -f $(type -p java))))
		if [[ -e "$jhome/lib/security/java.security" ]]; then
			export JAVA_HOME="$jhome"
		elif jhome=$(java -classpath ${Spath}/files/ getJavaHome); then
			export JAVA_HOME="$jhome"
		else
			errx "No java found, please install JRE"
		fi
	fi
#	if [[ -z "`grep 'JAVA_HOME' /root/.bashrc`" ]]; then
#		echo "export JAVA_HOME=${JAVA_HOME}" >> /root/.bashrc
#	fi
fi

# 	set path to ca cert file
if [[ -f "/etc/ssl/certs/java/cacerts" ]]; then
	javaCAcerts="/etc/ssl/certs/java/cacerts"
elif [[ -f "/etc/pki/java/cacerts" ]]; then
	javaCAcerts="/etc/pki/java/cacerts"
else
	javaCAcerts="${JAVA_HOME}/lib/security/cacerts"
fi

if [[ "${fticks}" == "y" ]]; then
	if ! type -t mvn >/dev/null; then
		if [[ ! -e "$builddir"/apache-maven-3.1.1 ]]; then
			fetchurl apache-maven-3.1.1-bin.tar.gz http://mirror.reverse.net/pub/apache/maven/maven-3/3.1.1/binaries/apache-maven-3.1.1-bin.tar.gz
			cd "$opttmp"
			tar -xf "$downloaddir"/apache-maven-3.1.1-bin.tar.gz
			mv apache-maven-3.1.1 "$builddir"
		fi
		export PATH="$builddir/apache-maven-3.1.1/bin:$PATH"
	fi

	fticks_commit=bf324601353fb64497d62d3716defc29953a478c
	if [[ ! -e "$builddir"/ndn-shib-fticks-$fticks_commit ]]; then
		fetchurl ndn-shib-fticks-$fticks_commit.tar.gz https://codeload.github.com/leifj/ndn-shib-fticks/tar.gz/$fticks_commit
		cd "$opttmp"
		tar xf "$downloaddir"/ndn-shib-fticks-$fticks_commit.tar.gz
		mv ndn-shib-fticks-$fticks_commit "$builddir"
		cd "$builddir"/ndn-shib-fticks-$fticks_commit
		if ! mvn; then
		    rm -rf "$builddir"/ndn-shib-fticks-$fticks_commit
		    exit 1
		fi
		software_changes=yes
	fi
fi

cd "$opttmp"
if [[ "$software_changes" == "yes" && ! -e "$opttmp/shibboleth-identityprovider-${shibVer}" ]]; then
	unzip -q "$downloaddir"/shibboleth-identityprovider-${shibVer}-bin.zip
	chmod -R 755 shibboleth-identityprovider-${shibVer}/install.sh
fi

mkdir -p "$opttmp/conf-build/idp"
if [[ -e "$opttmp/shibboleth-identityprovider-${shibVer}" ]]; then
	cp -a "$opttmp/shibboleth-identityprovider-${shibVer}"/src/installer/resources/conf-tmpl "$opttmp/conf-build/idp/conf-tmpl"
else
	cp -a "$builddir/shibboleth-identityprovider-${shibVer}"/src/installer/resources/conf-tmpl "$opttmp/conf-build/idp/conf-tmpl"
fi

cdpush "$opttmp/conf-build/idp"/conf-tmpl
quiet patch -F 5 <"$idp_config_patch_tmp"
cdpop

if [[ -e "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp ]]; then
	mktmp webapptmp
	cdpush "${Spath}"/files/webapp-config/recommended
	for f in $(find . -type f); do
		if file --brief "$f" | egrep ' text($|,)'; then
			if [[ -e "${Spath}"/files/webapp-config/dist/"$f" && -e "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/"$f" ]]; then
				diff -uw "${Spath}"/files/webapp-config/{dist,recommended}/"$f" >"$webapptmp" || :
				quiet patch -F 5 <"$webapptmp" "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/"$f"
			else
				cp "${Spath}"/files/webapp-config/recommended/"$f" "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/"$f"
			fi
			sed -e "$filtertokens" -i "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/"$f"
		else
			cp "${Spath}"/files/webapp-config/recommended/"$f" "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/"$f"
		fi
	done
	cdpop

	if [[ -n "$pnglogo" && -z "$pngmobilelogo" ]]; then
	    pngmobilelogo="$pnglogo"
	fi
	if [[ -n "$pngmobilelogo" && -z "$pnglogo" ]]; then
	    pnglogo="$pngmobilelogo"
	fi
	if [[ -n "$pnglogo" ]]; then
		cdpush "${Spath}"
		cp "$pnglogo" "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/images/logo.png
		cdpop
	fi
	if [[ -n "$pngmobilelogo" ]]; then
		cdpush "${Spath}"
		cp "$pngmobilelogo" "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/images/mobilelogo.png
		cdpop
	fi
	if [[ -n "$pngfederationlogo" ]]; then
		cdpush "${Spath}"
		cp "$pngfederationlogo" "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/images/federation-logo.png
		cdpop
	fi
fi

if [[ "${uapprove}" == "y" ]]; then
	if [[ -e "$opttmp/shibboleth-identityprovider-${shibVer}" ]]; then
		cp "$builddir"/uApprove-2.5.0/lib/*.jar "$opttmp/shibboleth-identityprovider-${shibVer}"/lib
		cp "$builddir"/uApprove-2.5.0/lib/jdbc/*.jar "$opttmp/shibboleth-identityprovider-${shibVer}"/lib
		mkdir "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/uApprove
		cp "$builddir"/uApprove-2.5.0/webapp/* "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/uApprove
	fi

	mktmp uapproveproperties
	cat "$builddir"/uApprove-2.5.0/manual/configuration/uApprove.properties >"$uapproveproperties"

	escapedorgdomain="${schachomeorganization//./\.}"

	# Don't ask about our own services.
	patch -F5 "$uapproveproperties" <<EOF
--- uApprove.properties    2013-11-04 16:54:31.973124177 +0100
+++ uApprove.properties.new        2013-11-04 16:55:34.130124415 +0100
@@ -9,15 +9,14 @@
 # List of service provider entity IDs.
 # The entries are interpreted as regular expression.
 # http://myregexp.com/ can assist you creating such expressions.
-services                    = ^https://.*\.example\.org/shibboleth$ \\
-                              ^https://sp\.other-example\.org/shibboleth$
+services                    = https://.*\.$escapedorgdomain/shibboleth$
 
 # Indicates if the list above should be interpreted as blacklist (true)
 # or as whitelist (false). If this value is set to true, users will not
 # see uApprove when trying to access matching services. If this value is
 # false, users will see uApprove only for the entities matching this list
 # but not for others.
-services.blacklist          = true
+services.blacklist          = true
 
 #---------------------------------------------------------------------#
 # View and Localization                                               #
EOF

	sed -i "$uapproveproperties" -re 's,^(tou\.enabled *)=.*$,\1= false,;'

	uapprovejdbcurl="jdbc:postgresql://$uapprove_db_host:5432/$uapprove_db_name?ssl=true"
	if [[ "$uapprove_db_host" == "localhost" || "$uapprove_db_host" == "localhost.localdomain" ]]; then
		uapprovejdbcurl="jdbc:postgresql://127.0.0.1:5432/$uapprove_db_name"
	fi

	pw=""
	if [[ -e "$installdir"/conf/uApprove.properties ]]; then
		pw=$(sed -nre <"$installdir"/conf/uApprove.properties 's,^database\.password *= *(.*)$,\1,p;')
		if ! env PGPASSWORD="$pw" psql --host=$uapprove_db_host --username=$uapprove_db_user $uapprove_db_name -c ''; then
			pw=""
		fi
	fi

	if [[ -z "$pw" ]]; then
		postgresql_db_create "$uapprove_db_host" "$uapprove_db_name" "$uapprove_db_user"
		cat "$builddir"/uApprove-2.5.0/manual/storage/{terms-of-use-schema,attribute-release-schema}.sql | env PGPASSWORD="$pw" psql --host=$uapprove_db_host --username=$uapprove_db_user $uapprove_db_name
	fi
		
	sed -i "$uapproveproperties" -re 's,^(database\.driver *)=.*$,\1= org.postgresql.Driver,;'
	sed -i "$uapproveproperties" -re 's,^(database\.url *)=.*$,\1= '"$uapprovejdbcurl"',;'
	sed -i "$uapproveproperties" -re 's,^(database\.username *)=.*$,\1= '$uapprove_db_user',;'
	sed -i "$uapproveproperties" -re 's,^(database\.password *)=.*$,\1= '$pw',;'
fi

for f in "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/*.{jsp,css} "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/uApprove/*.jsp; do
	if [[ ! -e "$f" ]]; then continue; fi
	if [[ -n "$pnglogo" ]]; then
		sed -i "$f" -e "s,images/dummylogo.png\" alt=\"[^\"]*\" ,images/logo.png\" alt=\"$certAcro\" ,g;"
		sed -i "$f" -e "s,uApprove/logo.png\" alt=\"[^\"]*\" ,images/logo.png\" alt=\"$certAcro\" ,g;"
		sed -i "$f" -e "s,images/dummylogo.png,images/logo.png,g;"
	fi
	if [[ -n "$pngmobilelogo" ]]; then
		sed -i "$f" -e "s,images/dummylogo-mobile.png\" alt=\"[^\"]*\" ,images/mobilelogo.png\" alt=\"$certAcro\" ,g;"
		sed -i "$f" -e "s,images/dummylogo-mobile.png,images/mobilelogo.png,g;"
	fi
	if [[ -n "$pngfederationlogo" ]]; then
		sed -i "$f" -e "s,uApprove/federation-logo.png,images/federation-logo.png,g;"
	fi
done

if [[ "${type}" = "cas" ]]; then
	if [[ -e "$opttmp/shibboleth-identityprovider-${shibVer}" ]]; then
		#copy cas depends into shibboleth
		cp "$builddir"/cas-client-3.2.1/modules/cas-client-core-3.2.1.jar "$opttmp/shibboleth-identityprovider-${shibVer}"/lib/
		cp "$builddir"/cas-client-3.2.1/modules/commons-logging-1.1.jar "$opttmp/shibboleth-identityprovider-${shibVer}"/lib/
		mkdir "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/WEB-INF/lib
		cp "$builddir"/cas-client-3.2.1/modules/cas-client-core-3.2.1.jar "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/WEB-INF/lib
		cp "$builddir"/cas-client-3.2.1/modules/commons-logging-1.1.jar "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/WEB-INF/lib
	fi
fi

if [[ "${fticks}" == "y" ]]; then
	if [[ -e "$opttmp/shibboleth-identityprovider-${shibVer}" ]]; then
		cp "$builddir"/ndn-shib-fticks-$fticks_commit/target/*.jar "$opttmp/shibboleth-identityprovider-${shibVer}"/lib
		cd "$opttmp"
	fi
fi

if [[ "${upgrade}" -eq 0 ]]; then

	cdpush $(mktemp -d)
	tmpfiles[${#tmpfiles[@]}]="$PWD"

	env LC_ALL=en_US.UTF-8 keytool -keystore "$javaCAcerts" -storepass changeit -list | fgrep -B 1 trustedCertEntry | fgrep fingerprint >trusted || :

	for ldapservername in ${ldapserver}; do
		# Download the cert chain from the LDAP server (hopefully, not verified)
		if ! openssl s_client -showcerts -connect "$ldapservername:636" >>certs 2>/dev/null <<<"QUIT"; then
			echo >&2 "Warning: Connecting to LDAP server $ldapservername with SSL failed."
		fi
	done

	declare linkdata="" line=""
	if fgrep 'END CERTIFICATE' certs >/dev/null; then
		# Split the chains in their links
		linkdata="" line=""
		{
		while read line; do
			linkdata="$linkdata
$line"
			if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
				# Is it self signed? (A root cert)
				issuer=$(openssl x509 -noout -issuer <<<"$linkdata"|sed -nre 's,^issuer= *,,p;')
				subject=$(openssl x509 -noout -issuer <<<"$linkdata"|sed -nre 's,^subject= *,,p;')
				if [[ "$issuer" == "$subject" ]]; then
					hasit=""
					fingerprint=""
					for fingerprint in $(openssl x509 -noout -fingerprint <<<"$linkdata" | sed -nre 's,^[^ ]+ Fingerprint= *,,p;' | sort -u); do
						if fgrep "$fingerprint" "$trusted" >/dev/null; then
							hasit=yes; break
						fi
					done
					if [[ -z "$hasit" && -n "$fingerprint" ]]; then
						echo >"rootcert-$fingerprint.pem" "$linkdata"
					fi
				fi
				linkdata=""
			fi
		done
		} <"$certs"
		
		for rootcerttmp in rootcert-*.pem; do
			if [[ -r "$rootcerttmp" ]]; then
				echo "Adding LDAP server certificate to java keystore..."
				openssl x509 -noout -text -in "$rootcerttmp"
				keytool -keystore "$javaCAcerts" -storepass changeit -import -alias "$ldapservername root cert" -file "$rootcerttmp"
			fi
		done
	fi

	cdpop
fi

if [[ -e "$opttmp/shibboleth-identityprovider-${shibVer}" ]]; then
	if [[ -e "$installdir" ]]; then
		xmlcheck "$installdir"/metadata/idp-metadata.xml
		cp "$installdir"/metadata/idp-metadata.xml "$opttmp/shibboleth-identityprovider-${shibVer}"/src/main/webapp/metadata.xml
	fi
	if [[ -e "$builddir/shibboleth-identityprovider-${shibVer}" ]]; then
		mv "$builddir/shibboleth-identityprovider-${shibVer}" "$builddir/shibboleth-identityprovider-${shibVer}".old.$ts
	fi
	mv "$opttmp/shibboleth-identityprovider-${shibVer}" "$builddir"
fi

# Do this late to reduce the risk of having to ask again if something fails.
text_input ldappass "LDAP bind password" "Please input the bind password for LDAP\n  $ldapbinddn" ""

if [[ -e "$installdir" ]]; then
	bupFile="$(mktemp -d)/backup-shibboleth-idp.${ts}.tar.gz"
	tar zcf "${bupFile}.new" -C "$(dirname "$installdir")" "$(basename "$installdir")"
	mv "${bupFile}"{.new,}
fi
	
if [[ -n "$software_changes" ]]; then
	cd "$builddir/shibboleth-identityprovider-${shibVer}"
	if [[ "${upgrade}" -eq 1 ]]; then
		# Don't overwrite certificates, metadata. Also doesn't overwrite config so we do that afterwards.
		echo "Running Shibboleth installer in upgrade mode..."
		sh install.sh -Didp.home.input="$installdir" -Dinstall.config=no
	else
		echo "Running Shibboleth installer in install mode..."
		sh install.sh -Didp.home.input="$installdir" -Didp.hostname.input="${certCN}" -Didp.keystore.pass="${pass}"

		if [[ "${idpurl}/idp/shibboleth" != "${entityid}" ]]; then
		    echo "Fixing up generated metadata..."
		    escapedbadentityid="${idpurl//./\.}/idp/shibboleth"
		    sed -i "$installdir"/metadata/idp-metadata.xml -re 's, entityID="'"${escapedbadentityid}"'", entityID="'"${entityid}"'",;'
		    sed -i "$installdir"/metadata/idp-metadata.xml -re 's,<shibmd:Scope regexp="false">[a-z0-9\.]+</shibmd:Scope>,<shibmd:Scope regexp="false">'"${scope}"'</shibmd:Scope>,g;'
		fi
	fi
fi

chmod 640 $installdir/credentials/idp.key

cp "${Spath}/config" "$installdir"/deploy-config

for f in "${Spath}"/files/metadata/*.xml; do
    if [[ -e "$f" ]]; then
	#xmlcheck "$f"
	installf="$installdir"/metadata/"$(basename "$f")"
	if [[ ! -e "$installf" ]] || ! cmp -s "$f" "$installf"; then
	    cp "$f" "$installf".new
	    mv "$installf".new "$installf"
	fi
    fi
done

cdpush "$opttmp/conf-build/idp"/conf-tmpl
for f in *.xml; do
	sed <"$f" >"$installdir/conf/$f.new" -e "$filtertokens"
	if fgrep xmlns: "$f" >/dev/null ; then
		xmlcheck "$f"
		xmlcheck "$installdir/conf/$f.new"
	fi
	if ! cmp -s "$installdir/conf/$f.new" "$installdir/conf/$f"; then
		mv "$installdir/conf/$f.new" "$installdir/conf/$f"
	fi
done
cdpop

if [[ -n "$uapproveproperties" ]]; then
	#xmlcheck "$builddir"/uApprove-2.5.0/manual/configuration/uApprove.xml
	cp "$builddir"/uApprove-2.5.0/manual/configuration/uApprove.xml "$installdir"/conf/uApprove.xml
	sed -i "$installdir"/conf/uApprove.xml -e "s,classpath:/configuration,file:$installdir/conf,g;"
	#xmlcheck "$installdir"/conf/uApprove.xml
	cp "$uapproveproperties" "$installdir"/conf/uApprove.properties
	chmod 640 "$installdir"/conf/uApprove.properties
fi

mktmp proptmp
if [[ -e "$installdir"/conf/attribute-resolver.properties ]]; then
	cat "$installdir"/conf/attribute-resolver.properties >"$proptmp"
fi

sed -i "$proptmp" -e '/^myldap\.url *=/d'
echo "myldap.url = $ldapurls" | native2ascii >>"$proptmp"

sed -i "$proptmp" -e '/^myldap\.basedn *=/d'
echo "myldap.basedn = $ldapbasedn" | native2ascii >>"$proptmp"

sed -i "$proptmp" -e '/^myldap\.binddn *=/d'
echo "myldap.binddn = $ldapbinddn" | native2ascii >>"$proptmp"

if [[ -n "$ldappass" ]]; then
	sed -i "$proptmp" -e '/^myldap\.password *=/d'
	echo "myldap.password = $ldappass" | native2ascii >>"$proptmp"
fi

sed -i "$proptmp" -e '/^myldap\.noredupersonninattr *=/d'
echo "myldap.noredupersonninattr = $ninc" | native2ascii >>"$proptmp"

sed -i "$proptmp" -e '/^org\.o *=/d'
echo "org.o = $certOrg" | native2ascii >>"$proptmp"

sed -i "$proptmp" -e '/^org\.c *=/d'
echo "org.c = $certC" | native2ascii >>"$proptmp"

sed -i "$proptmp" -e '/^org\.co *=/d'
echo "org.co = $certLongC" | native2ascii >>"$proptmp"

sed -i "$proptmp" -e '/^org\.noreduorgacronym *=/d'
echo "org.noreduorgacronym = $certAcro" | native2ascii >>"$proptmp"

sed -i "$proptmp" -e '/^org\.schachomeorganization *=/d'
echo "org.schachomeorganization = $schachomeorganization" | native2ascii >>"$proptmp"

if [[ "${targetedid}" == "y" ]]; then
	if [[ -z "$esalt" ]]; then
		esalt=$(mkpasswd -s 0 -l 58)
		echo "$esalt" >"$persistentid_salt_file"
	fi
	echo "targetedid.salt = $esalt" | native2ascii >>"$proptmp"

	sed -i "$proptmp" -e '/^targetedid\.jdbcdriver *=/d'
	echo "targetedid.jdbcdriver = org.postgresql.Driver" | native2ascii >>"$proptmp"

	targetedidurl="jdbc:postgresql://$targetedid_db_host:5432/$targetedid_db_name?ssl=true"
	if [[ "$targetedid_db_host" == "localhost" || "$targetedid_db_host" == "localhost.localdomain" ]]; then
		targetedidurl="jdbc:postgresql://127.0.0.1:5432/$targetedid_db_name"
	fi
	sed -i "$proptmp" -e '/^targetedid\.jdbcurl *=/d'
	echo "targetedid.jdbcurl = $targetedidurl" | native2ascii >>"$proptmp"

	sed -i "$proptmp" -e '/^targetedid\.jdbcusername *=/d'
	echo "targetedid.jdbcusername = $targetedid_db_user" | native2ascii >>"$proptmp"

	if [[ -n "$epass" ]]; then
		sed -i "$proptmp" -e '/^targetedid\.jdbcpassword *=/d'
		echo "targetedid.jdbcpassword = $epass" | native2ascii >>"$proptmp"
	fi
fi

mktmp sortedproptmp
sort -u "$proptmp" >"$sortedproptmp"

if ! cmp -s "$installdir"/conf/attribute-resolver.properties "$sortedproptmp"; then
	cp "$sortedproptmp" "$installdir"/conf/attribute-resolver.properties.new
	mv "$installdir"/conf/attribute-resolver.properties{.new,}
	software_changes=yes
fi

chmod 750 "$installdir"
chgrp tomcat "$installdir"

if [[ "${appserv}" = "jboss" ]]; then
	echo "Adding basic jboss init script to start on boot"
	cp ${Spath}/files/jboss.init /etc/init.d/jboss
	update-rc.d jboss defaults
fi

if [[ "${appserv}" = "tomcat" ]]; then
	mkdir -p /usr/share/tomcat6/endorsed
	for jar in "$builddir/shibboleth-identityprovider-${shibVer}/endorsed"/*.jar; do
		if [[ -e "$jar" ]] && [[ ! -s "/usr/share/tomcat6/endorsed/$(basename "$jar")" ]]; then
			cp "$jar" /usr/share/tomcat6/endorsed/
		fi
	done
	for jar in /usr/share/java/postgresql-jdbc.jar; do
		if [[ -e "$jar" ]] && [[ ! -s "/usr/share/tomcat6/endorsed/$(basename "$jar")" ]]; then
			ln -s "$jar" /usr/share/tomcat6/endorsed/
		fi
	done
	if [[ "$apachefrontend" == "n" ]] && [[ ! -e /usr/share/tomcat6/lib/tomcat6-dta-ssl-1.0.0.jar ]] && [[ ! -L /usr/share/tomcat6/lib/tomcat6-dta-ssl-1.0.0.jar ]]; then
		ln -s "$downloaddir"/tomcat6-dta-ssl-1.0.0.jar /usr/share/tomcat6/lib/tomcat6-dta-ssl-1.0.0.jar 
	fi

	# https://access.redhat.com/labs/jvmconfig/#/?jv=Open&c=lowPause&hs=2560&gl=1&lp=1&de=1&dc=2&ao=0
	javaopts='-server -XX:+DoEscapeAnalysis -XX:+UseCompressedOops -XX:+UseConcMarkSweepGC -XX:+CMSClassUnloadingEnabled -XX:+UseParNewGC -XX:+ExplicitGCInvokesConcurrent -XX:CMSInitiatingOccupancyFraction=80 -XX:CMSIncrementalSafetyFactor=20 -XX:+UseCMSInitiatingOccupancyOnly -XX:MaxTenuringThreshold=32 -XX:+UseLargePages -Xmx2560M -Xms2560M -verbose:gc -Xloggc:gc.log -XX:+PrintGCDetails -XX:+PrintGCTimeStamps'

	if [[ -e /etc/default/tomcat6 ]]; then
		mktmp tomcatconftmp
		cat /etc/default/tomcat6 >"$tomcatconftmp"
		if ! grep '^JAVA_OPTS=' "$tomcatconftmp" >/dev/null; then
			echo 'JAVA_OPTS="'"-Djava.endorsed.dirs=/usr/share/tomcat6/endorsed $javaopts"'"' >> "$tomcatconftmp"
		else
			sed -i "$tomcatconftmp" -e 's,^JAVA_OPTS=.*$,JAVA_OPTS="'"-Djava.endorsed.dirs=/usr/share/tomcat6/endorsed $javaopts"'",;'
		fi
		if ! grep '^AUTHBIND=' "$tomcatconftmp" >/dev/null; then
			echo "AUTHBIND=yes" >> "$tomcatconftmp"
		else
			sed -i "$tomcatconftmp" -e 's,^AUTHBIND=.*$,AUTHBIND=yes,;'
		fi
		if ! cmp -s /etc/default/tomcat6 "$tomcatconftmp"; then
			cp "$tomcatconftmp" /etc/default/tomcat6.new
			mv /etc/default/tomcat6{.new,}
			restorecon /etc/default/tomcat6 >/dev/null 2>&1 || :
			tomcat_opts_changes=yes
		fi
	fi

	if [[ -e /etc/sysconfig/tomcat6 ]]; then
		mktmp tomcatconftmp
		cat /etc/sysconfig/tomcat6 >"$tomcatconftmp"
		if ! grep '^JAVA_ENDORSED_DIRS=' "$tomcatconftmp" >/dev/null; then
			echo "JAVA_ENDORSED_DIRS=/usr/share/tomcat6/endorsed" >> "$tomcatconftmp"
		else
			sed -i "$tomcatconftmp" -e 's,^JAVA_ENDORSED_DIRS=.*$,JAVA_ENDORSED_DIRS=/usr/share/tomcat6/endorsed,;'
		fi
		if ! grep '^JAVA_OPTS=' "$tomcatconftmp" >/dev/null; then
			echo 'JAVA_OPTS="'"$javaopts"'"' >> "$tomcatconftmp"
		else
			sed -i "$tomcatconftmp" -e 's,^JAVA_OPTS=.*$,JAVA_OPTS="'"$javaopts"'",;'
		fi
		if ! cmp -s /etc/sysconfig/tomcat6 "$tomcatconftmp"; then
			cp "$tomcatconftmp" /etc/sysconfig/tomcat6.new
			mv /etc/sysconfig/tomcat6{.new,}
			restorecon /etc/sysconfig/tomcat6 >/dev/null 2>&1 || :
			tomcat_opts_changes=yes
		fi
	fi

	tomcatgroup=tomcat

	backup_file /etc/tomcat6/server.xml .orig

	if [[ "${upgrade}" -eq 0 ]]; then
		cp "$serverxmltmp" /etc/tomcat6/server.xml
		chgrp $tomcatgroup /etc/tomcat6/server.xml
		chmod 640 /etc/tomcat6/server.xml
	fi

	if [[ -d "/var/lib/tomcat6/webapps/ROOT" ]]; then
		mv /var/lib/tomcat6/webapps/ROOT /opt/disabled-var-lib-tomcat6-webapps-ROOT
	fi

	chgrp -R $tomcatgroup "$installdir"/metadata
	chmod -R 770 "$installdir"/metadata

	idplogdir=/usr/share/tomcat6/logs/shibboleth-idp
	mkdir -p "$idplogdir"
	chgrp -R $tomcatgroup "$idplogdir"
	chmod 770 "$idplogdir"
	
	if [[ ! -L "$installdir"/logs ]]; then
	    if [[ -e "$installdir"/logs ]]; then
		mv "$installdir"/logs "$installdir"/logs.old
	    fi
	    ln -s "$idplogdir" "$installdir"/logs
	fi
		
	chgrp -R $tomcatgroup "$installdir"/conf/*.properties
	chmod 640 "$installdir"/conf/*.properties
	
	if [[ -n "$software_changes" ]]; then
		cp "$installdir"/war/idp.war /usr/share/tomcat6/webapps/idp.war.new
		chgrp -R $tomcatgroup /usr/share/tomcat6/webapps/idp.war.new
		chmod 640 /usr/share/tomcat6/webapps/idp.war.new
		rm -rf /usr/share/tomcat6/webapps/idp.new
		mkdir /usr/share/tomcat6/webapps/idp.new
		cdpush /usr/share/tomcat6/webapps/idp.new
		jar -xf ../idp.war.new
		cdpop
	fi

	chgrp $tomcatgroup $installdir/credentials/idp.key
fi

fetchurl md-signer.crt.maybe-${mdSignerFinger} https://md.swamid.se/md/md-signer.crt
cFinger=$(openssl x509 -noout -fingerprint -sha1 -in "$downloaddir"/md-signer.crt.maybe-${mdSignerFinger} | cut -d\= -f2)
if [[ "${cFinger}" != "${mdSignerFinger}" ]]; then
	errx "Fingerprint error on md-signer.crt!"
fi

if [[ -e "$installdir"/credentials/md-signer.crt ]] && cmp -s "$downloaddir"/md-signer.crt.maybe-${mdSignerFinger} "$installdir"/credentials/md-signer.crt; then
	: already ok
else
	cp "$downloaddir"/md-signer.crt.maybe-${mdSignerFinger} "$installdir"/credentials/md-signer.crt
fi

if [[ "${fticks}" == "y" ]]; then
	if [[ -e "$fticks_key_file" && ! -e "$installdir"/conf/fticks-key.txt ]]; then
		cp -a "$fticks_key_file" "$installdir"/conf/fticks-key.txt
	fi
	touch "$installdir"/conf/fticks-key.txt
	if [[ "${appserv}" = "tomcat" ]]; then
		chgrp $tomcatgroup "$installdir"/conf/fticks-key.txt
		chmod 770 "$installdir"/conf/fticks-key.txt
	fi
fi

xmlcheck ${Spath}/xml/google.xml
cat ${Spath}/xml/google.xml | perl -npe "s/GoOgLeDoMaIn/${googleDom}/" > "$installdir"/metadata/google.xml
xmlcheck "$installdir"/metadata/google.xml

if [[ "$apachefrontend" == "y" ]]; then
	mktmp httpdconftmp
	cat >"$httpdconftmp" <<EOF
<VirtualHost $idphostname:443>
ErrorLog logs/shibboleth-idp-ssl_error_log
TransferLog logs/shibboleth-idp-ssl_access_log
LogLevel warn
SSLEngine on
SSLProtocol all -SSLv2 -SSLv3
SSLCipherSuite ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW
SSLCertificateFile /etc/pki/tls/certs/localhost.crt
SSLCertificateKeyFile /etc/pki/tls/private/localhost.key
EOF
	if [[ -e /etc/pki/tls/certs/server-chain.crt ]]; then
		cat >>"$httpdconftmp" <<EOF
SSLCertificateChainFile /etc/pki/tls/certs/server-chain.crt
EOF
	fi
	cat >>"$httpdconftmp" <<EOF
<Files ~ "\.(cgi|shtml|phtml|php3?)$">
    SSLOptions +StdEnvVars
</Files>
<Directory "/var/www/cgi-bin">
    SSLOptions +StdEnvVars
</Directory>
SetEnvIf User-Agent ".*MSIE.*" \
         nokeepalive ssl-unclean-shutdown \
         downgrade-1.0 force-response-1.0
CustomLog logs/shibboleth-idp-ssl_request_log \
          "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"

<IfModule mod_proxy_ajp.c>
    ProxyRequests Off
    <Proxy ajp://127.0.0.1:8009>
        Allow from all
    </Proxy>
    ProxyPass /idp ajp://127.0.0.1:8009/idp retry=5
</IfModule>

Redirect / https://www.$schachomeorganization/
</VirtualHost>

Listen 8443
<VirtualHost $idphostname:8443>
ErrorLog logs/shibboleth-idp-ssl_error_log
TransferLog logs/shibboleth-idp-ssl_access_log
LogLevel warn
SSLEngine on
SSLProtocol all -SSLv2 -SSLv3
SSLCipherSuite ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW
SSLCertificateFile $installdir/credentials/idp.crt
SSLCertificateKeyFile $installdir/credentials/idp.key
SSLVerifyClient optional_no_ca
SSLVerifyDepth 10
EOF
	if [[ -e /etc/pki/tls/certs/server-chain.crt ]]; then
		cat >>"$httpdconftmp" <<EOF
SSLCertificateChainFile /etc/pki/tls/certs/server-chain.crt
EOF
	fi
	cat >>"$httpdconftmp" <<EOF
<Files ~ "\.(cgi|shtml|phtml|php3?)$">
    SSLOptions +StdEnvVars
</Files>
<Directory "/var/www/cgi-bin">
    SSLOptions +StdEnvVars
</Directory>
SetEnvIf User-Agent ".*MSIE.*" \
         nokeepalive ssl-unclean-shutdown \
         downgrade-1.0 force-response-1.0
CustomLog logs/shibboleth-idp-ssl_request_log \
          "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"

<IfModule mod_proxy_ajp.c>
    ProxyRequests Off
    <Proxy ajp://127.0.0.1:8009>
        Allow from all
    </Proxy>
    ProxyPass /idp ajp://127.0.0.1:8009/idp retry=5
</IfModule>

Redirect / https://www.$schachomeorganization/
</VirtualHost>
EOF
	if [[ -d /etc/httpd/conf.d ]]; then
		cp "$httpdconftmp" /etc/httpd/conf.d/zz-80-shibboleth-idp.conf
		chmod a+r /etc/httpd/conf.d/zz-80-shibboleth-idp.conf
	fi
fi

if [[ "${appserv}" = "tomcat" ]]; then
	restorecon -r /usr/share/tomcat6 /var/lib/tomcat6 /var/log/tomcat6 /usr/share/java/tomcat6 /var/cache/tomcat6 /etc/tomcat6/ >/dev/null 2>&1 || :
	if [[ "$software_changes" == "yes" ]]; then
		service tomcat6 stop || :
		if [[ -e /usr/share/tomcat6/webapps/idp.war.new ]]; then
			rm -rf /var/cache/tomcat6/work/* /var/cache/tomcat6/temp/*
			rm -rf /usr/share/tomcat6/webapps/idp
			mv /usr/share/tomcat6/webapps/idp.war{.new,}
			mv /usr/share/tomcat6/webapps/idp{.new,}
			#mv "$tomcatconfdir"/Catalina/localhost/idp.xml{.new,}
		fi
		service tomcat6 start
	elif [[ "$tomcat_opts_changes" == "yes" ]]; then
		service tomcat6 restart
	fi
	if [[ "${upgrade}" -eq 1 ]] && [[ "$apachefrontend" == "y" ]]; then
	    service httpd restart
	    declare -i httpdtries=0
	    echo -n "Restarting Apache until the service is up..."
	    while :; do
		if curl 2>/dev/null "${idpurl}/idp/shibboleth" | fgrep >/dev/null entityID=; then
		    echo " ok"
		    break
		fi
		echo -n .
		sleep 3
		service httpd restart >/dev/null 2>&1
		((httpdtries++)) || :
		if (( httpdtries > 30 )); then
		    echo " giving up"
		    break
		fi
	    done
	fi
fi

echo -e "\n\n\n"

if [[ -e ${bupFile} ]]; then
	echo "A backup of the previos shibboleth installation is saved in: ${bupFile}"
	echo ""
fi

if [[ "${upgrade}" -eq 0 ]]; then
	echo "Installation done. Now register in your federation, the certificate for IdP metadata is in the file: $installdir/credentials/idp.crt"
	echo ""
	echo "Use either 'request-cert' and 'install-cert' or 'self-signed-cert' to"
	echo "generate a web server certificate if you have not done so already."
	if [[ "$apachefrontend" == "y" ]]; then
		echo "Start Apache httpd when a web server certificates has been configured."
	else
		echo "Restart services when a web server certificates has been configured."
		echo "If required, run"
		echo " /root/certs/.../install-localhost-chain-in-java-keystore"
	fi
fi
echo "Logs are in: /usr/share/tomcat6/logs/"
echo ""

