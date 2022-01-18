#!/usr/bin/env sh

## StackScript for installing a Wordpress LEMP stack on el8-compatible
## distros.

## StackScript User Defined Fields
# <UDF name="udf_sudo_user" label="Login username for this Linode instance, with sudo access for system management." default="" example="linus" />

# <UDF name="udf_sudo_user_password" label="A unique login password for this Linode instance, with sudo access for system management." default="" example="t0rva1d1s" />

# <UDF name="udf_site_url" label="Domain name(s) separated by a single space  for Wordpress site." default="your-domainname.com" example="sample-site.com" />

# <UDF name="udf_mysql_root_password" label="MariaDB Root Password. " default="" example="" />

PRGNAM="wordpress-stackscript"
VERSION="0.3"

site_url="${udf_site_url}"
sudo_user="${udf_sudo_user}"
sudo_user_password="${udf_sudo_user_password}"

php_version="${udf_php_version}"

mysql_root_password="${udf_mysql_root_password}"

# TODO: perhaps just create these automatically
# the details will be in the wp-config.php file

wordpress_db_name="${udf_wordpress_db_name}"
wordpress_db_user="${udf_wordpress_db_user}"
wordpress_db_password="${udf_wordpress_db_password}"

linode_id="${LINODE_ID}"
linode_ram="${LINODE_RAM}"
linode_datacenterid="${LINODE_DATACENTERID}"

www_user="${www_user:-nginx}"
www_group="${www_group:-nginx}"

wwwroot_path="${wwwroot_path:-/var/www}"
log_path="${log_path:-/var/log}"
install_log="${log_path}/${PRGNAM}-install.log"

flog_this() {
    printf "[%s]:\n %s\n" "$(date)" "$1"
    return $?
}

fcheck_distro() {
    if [ -r /etc/rhel-release ]; then
        __version="$(awk -F= '/^VERSION_ID/{print $2}' /etc/os-release)"

        case "$__version" in
        "8*")
            return $? ;;
        *)
            flog_this "Error. Script supports el8.* ${__version} detected."
            exit 1 ;;
        esac
    else
        flog_this "Error. Script supports el8.* ${__version} detected."
        exit 1 ;;
    fi

    return $?
}

fel8_setup() {
    printf "%s: Updating system with DNF...\n" "$(date)"

    /usr/bin/dnf update -y

    /usr/bin/firewall-cmd --permanent --add-service=http --add-service=ssh
    /usr/bin/firewall-cmd --reload

    /usr/bin/dnf install -y epel-release
    /usr/bin/dnf update -y
    /usr/bin/dnf install -y fail2ban-all

    /usr/bin/dnf config-manager --set-enabled powertools
    /usr/bin/dnf module reset php -y
    /usr/bin/dnf module enable php:${php_version} -y

    /usr/bin/dnf install -y curl nginx mariadb-server php php-fpm \
        php-mysqlnd php-opcache php-gd php-curl php-cli php-json php-xml 


    /usr/bin/systemctl enable nginx mariadb php-fpm fail2ban
    /usr/bin/systemctl start nginx mariadb php-fpm fail2ban

    # TODO: conditional php version install; with extra repo
    # TODO: check into whether to do the same with mariadb/nginx
    # TODO: wp-cli install
    # TODO: certbot install and appropriate plugin

    return $?
}

ffail2ban_setup() {
    flog_this "Setting up fail2ban..."
    cat << EOF > /etc/fail2ban/jail.d/00-sshd.conf
[sshd]
enabled = true
EOF

    # TODO: Add NGINX and maybe Wordpress specific jails

    systemctl restart fail2ban
    return $?
}

fsite_user_setup(){
    __site_url="$1"
    __site_user="$2"

    useradd ${__site_user} -m -d ${wwwroot_path}/${__site_url} || \
        flog_this "Error creating site user for ${__site_user}".

    return $?
}

fmysql_setup(){

    # Secure the mysql installation
    mysql -sfu root  << EOF
UPDATE mysql.user SET Password=PASSWORD('${mysql_root_password}') WHERE User='root';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF

    # TODO: Either use wp-cli for database creation or make this loopable
    # for multiple accounts

    # Install the database
#    mysql -sfu root -p ${mysql_root_password} << EOF
#CREATE DATABASE ${wordpress_db_name};
#CREATE USER ${wordpress_db_user}@localhost IDENTIFIED BY '${wordpress_db_password}';
#GRANT ALL ON ${wordpress_db_name}.* TO ${wordpress_db_user}@localhost;
#FLUSH PRIVILEGES;
#EOF
    
    return $?
}

fnginx_setup() {
    # Usage: function <site_url> <site_user>
    __site_url="$1"
    __site_user="$2"

    # Create paths for site
    # TODO:: is this the correct place to do this?

    mkdir -p ${wwwroot_path}/${__site_url}/{public,cache,logs}
    chown -R ${__site_user}:${__site_user} ${wwwroot_path}/${__site_url}

    # TODO: will certbot be able to use this conf with 443 or does it need
    # to be 80 first and certbot will do the details...
    # or I suppose I could just cert-only; in that case...
    # TODO: add letsencrypt paths here (see above)

    cat << EOF > /etc/nginx/conf.d/${__site_url}.conf
fastcgi_cache_path ${wwwroot_path}/${__site_url}/cache levels=1:2 keys_zone=${__site_url}:100m inactive=60m;

server {
    listen 443 ssl http2;

    server_name ${__site_url} www.${__site_url};
    root ${wwwroot_path}/${__site_url}/public;
    index index.php;

    # Allow per-site logs
    access_log ${wwwroot_path}/${__site_url}/logs/access.log;
    error_log ${wwwroot_path}/${__site_url}/logs/error.log;

    # Default server block rules
    include global/server/defaults.conf;

    # Default Fastcgi cache rules
    include global/server/fastcgi-cache.conf;

    # SSL rules
    include global/server/ssl.conf;

    location / {
    try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php$ {
    try_files \$uri =404;
    include global/fastcgi_params;

    fastcgi_pass unix:/run/php-fpm/${site_user}.sock;
    
    # Skip cache based on rules in server/fastcgi-cache.conf.
	fastcgi_cache_bypass \$skip_cache;
	fastcgi_no_cache \$skip_cache;

	# Define memory zone for caching. Should match key_zone in fastcgi_cache_path above.
	fastcgi_cache ${__site_url};

	# Define caching time.
	fastcgi_cache_valid 60m;
    }

# Redirect http to https
server {
	listen 80;
	listen [::]:80;
	server_name ${__site_url} www.${__site_url};

	return 301 https://${__site_url}$request_uri;
}

# Redirect www to non-www
server {
	listen 443;
	listen [::]:443;
	server_name www.${__site_url};

	return 301 https://${__site_url}$request_uri;
}
EOF
    
    nginx -t || flog_this "Error in nginx config." || exit 1
    systemctl restart nginx.service
    return $?
}

fsetup_phpfpm() {
    # Usage: function <site_url> <site_user>
    __site_url="$1"
    __site_user="$2"

    # Update generic PHP-FPM pool with correct permissions
    cp -a /etc/php-fpm.d/www.conf /etc/php-fpm.d/www-dist.conf
    sed -i -e "s/^user =.*/user = ${www_user}/g" \
        -e "s/^group =.*/group = ${www_group}/g" \
        /etc/php-fpm.d/www.conf

    # Create unique FPM pool for each site for security and good health.
    cat << EOF > /etc/php-fpm.d/${__site_user}.conf
[${site_user}]
user = ${__site_user}
group = ${__site_user}

listen = /run/php-fpm/php${php_version}-${site_user}.sock
listen.owner = ${__site_user}
listen.group = ${www_group}
listen.mode = 0660

pm = dynamic
pm.max_children = 5
pm.start_servers = 1
pm.min_spare_servers = 1
pm.max_spare_servers = 1
pm.max_requests = 500

php_admin_value[error_log]=${wwwroot_path}/${__site_url}/logs/debug.log
EOF

    systemctl restart php-fpm nginx
    return $?
}

fphp_setup() {

    cp -a /etc/php.ini /etc/php-dist.ini
    sed -i -e 's/^post_max_size.*/post_max_size = 64M/g' \
        -e 's/^memory_limit.*/memory_limit = 256M/g' \
        -e 's/^max_execution_time.*/max_execution_time = 300/g' \
        -e 's/upload_max_filesize.*/upload_max_filesize = 32M/g' \
        /etc/php.ini

    return $?
}

fwordpress_setup() {
    flog_this "Wordpress not configuerd."
    return $?
}

fcertbot_setup() {
    # TODO: Add certbot instructions. 
    flog_this "Certbot not configured."
    return $?
}

fsudo_user_setup() {

    useradd -p ${sudo_user_password} -m -G wheel,${www_group} -U ${sudo_user}
    cp -a /root/.ssh /home/${sudo_user}
    chown -R ${sudo_user}:${sudo_user} /home/${sudo_user}
    chmod 700 /home/${sudo_user}/.ssh
    chmod 600 /home/${sudo_user}/.ssh/*
    return $?

}

fpost_install() {
    
    # Restrict remote ssh access to non-root users via ssh-keys
    sed -i -e 's/^PermitRootLogin.*/PermitRootLogin no/g' \
        -e 's/^PasswordAuthentication.*/PasswordAuthentication no/g' \
        -e 's/^\#PubkeyAuthentication.*/PubkeyAuthentication yes/g'
        /etc/ssh/sshd_config

    systemctl restart sshd.service

    if [ "$auto_updates" = "yes" ]; then
        # Enable automatic updates
        dnf install -y dnf-automatic

        sed -i -e 's/^apply_updates.*/apply_updates = yes/g' \
            -e 's/^emit_via.*/emit_via = motd,stdio/g' \
            /etc/dnf/automatic.conf

        systemctl enable --now dnf-automatic.timer
    fi

    # TODO: Edit the motd for first user login
}


# TODO: case conditionals for passed arguments
# TODO: loop the functions with multiple domains
# TODO: create a function or sed that creates site_user from site_url

touch "$install_log"

#fcheck_distro >> "$install_log"
fel8_setup >> "$install_log"
ffail2ban_setup >> "$install_log"
fsite_user_setup >> "$install_log"
fmysql_setup >> "$install_log"
#fphp_setup >> "$install_log"
#fnginx_setup >> "$install_log"
#fwordpress_setup >> "$install_log"
#fcertbot_setup >> "$install_log"
fsudo_user_setup >> "$install_log"
fpost_install >> "$install_log"

exit 0
