#!/usr/bin/bash

## StackScript for installing a LEMP stack on el8-compatible distros
## for one or more Wordpress installs.

## StackScript User Defined Fields
#SUDO_USER
# <UDF name="SUDO_USER" label="'sudo' user for system management. You need at least one ssh key assigned to the Linode."/>
# SUDO_USER_PASSWORD
# <UDF name="SUDO_USER_PASSWORD" label="Password for sudo user."/>
# SITE_URLS
# <UDF name="SITE_URLS" label="Domain name(s) separated by a comma for Wordpress site." example="example.com, sample-site.com, yourdomain.org" />
# MYSQL_ROOT_PASSWORD
# <UDF name="MYSQL_ROOT_PASSWORD" label="MariaDB Root Password. Save and keep in a secure location." />
# PHP_VERSION
# <UDF name="PHP_VERSION" label="Choose PHP version for Wordpress." default="7.4" oneof="7.4,8.0,8.1" />
# AUTO_UPDATE
# <UDF name="AUTO_UPDATE" label="Auto update the distro?" default="Yes" example="" oneof="Yes,No" />

PRGNAM="wordpress-stackscript-el8"
VERSION="0.6"

SITE_URLS="$SITE_URLS"
SUDO_USER="$SUDO_USER"
SUDO_USER_PASSWORD="$SUDO_USER_PASSWORD"
MYSQL_ROOT_PASSWORD="$MYSQL_ROOT_PASSWORD"
PHP_VERSION="${PHP_VERSION:-7.4}"
AUTO_UPDATE="${AUTO_UPDATE:-Yes}"

LINODE_ID="$LINODE_ID"
LINODE_RAM="$LINODE_RAM"
LINODE_DATACENTERID="$LINODE_DATACENTERID"

WWW_USER="${WWW_USER:-nginx}"
WWW_GROUP="${WWW_GROUP:-nginx}"
SITE_GROUP="${SITE_GROUP:-www-sites}"

WWWROOT_DIR="${WWWROOT_DIR:-/var/www}"
WP_CLI="/usr/local/bin/wp"

LOG_PATH="${LOG_PATH:-/var/log}"
INSTALL_LOG="${LOG_PATH}/${PRGNAM}-install.log"

####################
# Useful Functions #
####################

flog_this() {
    printf "[%s]\n%s\n\n" "$(date)" "$1" >> "$INSTALL_LOG"
    return $?
}

flog_error() {
    printf "\u001b[31;1m[%s]\nERROR: %s\n\n\033[m" "$(date)" "$1" >> "$INSTALL_LOG"
    return $?
}

fpassword_gen() {
    flog_this "Generating password..."
    __return="$(curl -s 'https://www.random.org/strings/?num=1&len=16&digits=on&upperalpha=on&loweralpha=on&unique=on&format=plain&rnd=new')">/dev/null
    case "$__return" in
        Error*) __return="$(< /dev/urandom tr -dc A-Za-z0-9_ | head -c16)" ;;
    esac

    prtinf "%s" "$__return"
}

################
# GLOBAL SETUP #
################

fcheck_distro() {
    if [ -x /usr/bin/dnf ]; then
        __version="$(awk -F= '/^VERSION_ID/{print $2}' /etc/os-release | tr -d '"')"
        case "$__version" in
        8*)
            flog_this "EL version ${__version} confirmed and compatible."
            return 0 ;;
        *)
            flog_error "Error. Script supports el8.* ${__version} detected."
            return 1 ;;
        esac
    else
        flog_error "Not a compatile EL system."
        return 1
    fi
}

fel8_setup() {

    # Initial update
    /usr/bin/dnf update -y

    # Set-up firewall
    /usr/bin/firewall-cmd --permanent --add-service=http
    /usr/bin/firewall-cmd --reload

    # Let's get fail2ban
    /usr/bin/dnf install -y epel-release
    /usr/bin/dnf update -y
    /usr/bin/dnf install -y fail2ban-all

    # Enable powertools
    /usr/bin/dnf config-manager --set-enabled powertools

    # Set desired php version
    case "$(echo ${PHP_VERSION} | tr -d '"')" in
        8*)
            flog_this "PHP version ${PHP_VERSION}"
            /usr/bin/dnf install -y dnf-utils \
                'http://rpms.remirepo.net/enterprise/remi-release-8.rpm'

            /usr/bin/dnf module reset php -y
            /usr/bin/dnf module enable php:remi-${PHP_VERSION} -y
            ;;
        7.4)
            flog_this "PHP version ${PHP_VERSION}"
            /usr/bin/dnf module reset php -y
            /usr/bin/dnf module enable php:${PHP_VERSION} -y
            ;;
    esac

    # Install everything
    usr/bin/dnf install -y curl wget nginx mariadb-server php php-fpm \
        php-mysqlnd php-opcache php-gd php-curl php-cli php-json php-xml \
        || flog_error 'line 119'

    /usr/bin/systemctl enable --now nginx mariadb php-fpm fail2ban \
        || flog_error 'line 121'

    # wp-cli install
    cd /tmp || flog_error 'line 132'
    curl -O 'https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar' || flog_error 'line 135'
    chmod +x wp-cli.phar || flog_error "line 126"
    cp wp-cli.phar /usr/local/bin/wp || flog_error "line 127"

    wget 'https://github.com/wp-cli/wp-cli/raw/master/utils/wp-completion.bash' || flog_error 'line 132'
    cp wp-completion.bash /etc/bash_completion.d/

    # TODO: certbot install and appropriate plugin

    # Create site-user for all sites
    groupadd site-user

    return $?
}

ffail2ban_setup() {
    cat << EOF > /etc/fail2ban/jail.d/00-sshd.conf
[sshd]
enabled = true
EOF

    # TODO: Add NGINX and maybe Wordpress specific jails

    systemctl restart fail2ban || flog_error "line 149"
    return $?
}

fmysql_setup(){
    # Secure the mysql installation
    mysql -u root  << EOF
UPDATE mysql.user SET Password=PASSWORD('${MYSQL_ROOT_PASSWORD}') WHERE User='root';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\\_%';
FLUSH PRIVILEGES;
EOF
    return $?
}

fnginx_setup() {

    cp /etc/nginx/nginx.conf /etc/nginx/nginx-dist.conf || \
        flog_error "line 168"
    cat << EOF > /etc/nginx/nginx.conf
# Modified by ${PRGNAM} stackscript
# For more information on configuration, see:
#   * Official English Documentation: http://nginx.org/en/docs/
#   * Official Russian Documentation: http://nginx.org/ru/docs/

user nginx;
worker_processes auto;
worker_rlimit_nofile 8192;
pid /run/nginx.pid;

# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 8000;
    multi_accept on;
}

http {
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    # Default logs
    error_log /var/log/nginx/error.log warn;
    access_log  /var/log/nginx/access.log  main;

    sendfile                on;
    tcp_nopush              on;
    tcp_nodelay             on;
    keepalive_timeout       15;
    client_body_timeout     30;
    client_header_timeout   30;
    send_timeout            30;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Some WP plugins that push large amounts of data via cookies
	# can cause 500 HTTP errors if these values aren't increased.
	fastcgi_buffers 16 16k;
	fastcgi_buffer_size 32k;

    # Gzip
    include /etc/nginx/conf.d/global/gzip.conf;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;

    # Sites
    include /etc/nginx/conf.d/sites/*.conf;

}
EOF

    mkdir -p /etc/nginx/conf.d/global
    cat << EOF > /etc/nginx/conf.d/global/gzip.conf
# Enable Gzip compression.
gzip on;

# Disable Gzip on IE6.
gzip_disable "msie6";

# Allow proxies to cache both compressed and regular version of file.
# Avoids clients that don't support Gzip outputting gibberish.
gzip_vary on;

# Compress data, even when the client connects through a proxy.
gzip_proxied any;

# The level of compression to apply to files. A higher compression level increases
# CPU usage. Level 5 is a happy medium resulting in roughly 75% compression.
gzip_comp_level 5;

# The minimum HTTP version of a request to perform compression.
gzip_http_version 1.1;

# Don't compress files smaller than 256 bytes, as size reduction will be negligible.
gzip_min_length 256;

# Compress the following MIME types.
gzip_types
	application/atom+xml
	application/javascript
	application/json
	application/ld+json
	application/manifest+json
	application/rss+xml
	application/vnd.geo+json
	application/vnd.ms-fontobject
	application/x-font-ttf
	application/x-web-app-manifest+json
	application/xhtml+xml
	application/xml
	font/opentype
	image/bmp
	image/svg+xml
	image/x-icon
	text/cache-manifest
	text/css
	text/plain
	text/vcard
	text/vnd.rim.location.xloc
	text/vtt
	text/x-component
	text/x-cross-domain-policy;
  # text/html is always compressed when enabled.
EOF

    mv /etc/nginx/default.d/php.conf /etc/nginx/default.d/php.conf.old || flog_error "line 345"

    cat << EOF > /etc/nginx/default.d/ssl.conf
# SSL Rules
# Generic SSL enhancements. Use https://www.ssllabs.com/ssltest/ to test
# and recommend further improvements.

# Don't use outdated SSLv3 protocol. Protects against BEAST and POODLE attacks.
ssl_protocols TLSv1.2;

# Use secure ciphers
ssl_ciphers EECDH+CHACHA20:EECDH+AES;
ssl_ecdh_curve X25519:prime256v1:secp521r1:secp384r1;
ssl_prefer_server_ciphers on;

# Define the size of the SSL session cache in MBs.
ssl_session_cache shared:SSL:10m;

# Define the time in minutes to cache SSL sessions.
ssl_session_timeout 1h;

# Use HTTPS exclusively for 1 year, uncomment one. Second line applies to subdomains.
add_header Strict-Transport-Security "max-age=31536000;";
# add_header Strict-Transport-Security "max-age=31536000; includeSubdomains;";
EOF

    cat << EOF > /etc/nginx/default.d/fastcgi-cache.conf
# The key to use when saving cache files, which will run through the MD5 hashing algorithm.
fastcgi_cache_key "\$scheme\$request_method\$host\$request_uri";

# If an error occurs when communicating with FastCGI server, return cached content.
# Useful for serving cached content if the PHP process dies or timeouts.
fastcgi_cache_use_stale error timeout updating invalid_header http_500;

# Allow caching of requests which contain the following headers.
fastcgi_ignore_headers Cache-Control Expires Set-Cookie;

# Show the cache status in server responses.
add_header Fastcgi-Cache \$upstream_cache_status;

# Don't skip by default
set \$skip_cache 0;

# POST requests and urls with a query string should always go to PHP
if (\$request_method = POST) {
	set \$skip_cache 1;
}

if (\$query_string != "") {
	set \$skip_cache 1;
}

# Don't cache URIs containing the following segments
if (\$request_uri ~* "/wp-admin/|/wp-json/|/xmlrpc.php|wp-.*.php|/feed/|index.php|sitemap(_index)?.xml|/cart/|/checkout/|/my-account/") {
	set \$skip_cache 1;
}

# Don't use the cache for logged in users or recent commenters
if (\$http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in|edd_items_in_cart|woocommerce_items_in_cart") {
	set \$skip_cache 1;
}
EOF

    cat << EOF > /etc/nginx/default.d/exclusions.conf
# Deny all attempts to access hidden files such as .htaccess, .htpasswd, .DS_Store (Mac).
# Keep logging the requests to parse later (or to pass to firewall utilities such as fail2ban)
location ~* /\.(?!well-known\/) {
	deny all;
}

# Prevent access to certain file extensions
location ~\.(ini|log|conf)$ {
	deny all;
}

# Deny access to any files with a .php extension in the uploads directory
# Works in sub-directory installs and also in multisite network
# Keep logging the requests to parse later (or to pass to firewall utilities such as fail2ban)
location ~* /(?:uploads|files)/.*\.php$ {
	deny all;
}
EOF

    cat << EOF > /etc/nginx/default.d/security.conf
# Generic security enhancements. Use https://securityheaders.io to test
# and recommend further improvements.

# Hide Nginx version in error messages and reponse headers.
server_tokens off;

# Don't allow pages to be rendered in an iframe on external domains.
add_header X-Frame-Options "SAMEORIGIN" always;

# MIME sniffing prevention
add_header X-Content-Type-Options "nosniff" always;

# Enable cross-site scripting filter in supported browsers.
add_header X-Xss-Protection "1; mode=block" always;

# Whitelist sources which are allowed to load assets (JS, CSS, etc). The following will block
# only none HTTPS assets, but check out https://scotthelme.co.uk/content-security-policy-an-introduction/
# for an in-depth guide on creating a more restrictive policy.
# add_header Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval';" always;
EOF

    cat << EOF > /etc/nginx/default.d/static-files.conf

# Don't cache appcache, document html and data.
location ~* \.(?:manifest|appcache|html?|xml|json)$ {
	expires 0;
}

# Cache RSS and Atom feeds.
location ~* \.(?:rss|atom)$ {
	expires 1h;
}

# Caches images, icons, video, audio, HTC, etc.
location ~* \.(?:jpg|jpeg|gif|png|ico|cur|gz|svg|mp4|ogg|ogv|webm|htc)$ {
	expires 1y;
	access_log off;
}

# Cache svgz files, but don't compress them.
location ~* \.svgz$ {
	expires 1y;
	access_log off;
	gzip off;
}

# Cache CSS and JavaScript.
location ~* \.(?:css|js)$ {
	expires 1y;
	access_log off;
}

# Cache WebFonts.
location ~* \.(?:ttf|ttc|otf|eot|woff|woff2)$ {
	expires 1y;
	access_log off;
	add_header Access-Control-Allow-Origin *;
}

# Don't record access/error logs for robots.txt.
location = /robots.txt {
	try_files \$uri \$uri/ /index.php?\$args;
	access_log off;
	log_not_found off;
}
EOF

    nginx -t || flog_this "Error in nginx config."
    systemctl restart nginx.service
    return $?
}


fphp_setup() {

    cp -a /etc/php.ini /etc/php-dist.ini || flog_error "line 594"
    sed -i -e 's/^post_max_size.*/post_max_size = 64M/g' \
        -e 's/^memory_limit.*/memory_limit = 256M/g' \
        -e 's/^max_execution_time.*/max_execution_time = 300/g' \
        -e 's/upload_max_filesize.*/upload_max_filesize = 32M/g' \
        /etc/php.ini

    return $?
}

######################
# SITE SPECFIC SETUP #
######################

fsite_user_setup(){
    __site_url="$1"
    __site_user="$2"

    flog_this "Setting up site user for: "${__site_user}"."

    useradd "${__site_user}" -m -d "${WWWROOT_DIR}"/"${__site_url}" -G "${SITE_GROUP}" -U || flog_error "Line 522 ; User "${__user}", homedir "${WWWROOT_DIR}"/"${__site_url}" sitegroup "${SITE_GROUP}""

    for dir in public config cache logs; do
        mkdir -p "${WWWROOT_DIR}"/"${__site_url}"/"${dir}" || \
            flog_error "line 525"
    done
    mkdir -p "${WWWROOT_DIR}"/"${__site_url}"/public/core || flog_error "528"
    mkdir -p "${WWWROOT_DIR}"/"${__site_url}"/public/content || flog_error "529"

    chown -R "${__site_user}":"${__site_user}" "${WWWROOT_DIR}"/"${__site_url}" || \
        flor_error "531"
    chmod 750 "${WWWROOT_DIR}"/"${__site_url}" || flog_error "533"
    return $?
}

fsite_setup() {
    # Usage: function <SITE_URLS> <site_user>
    __site_url="$1"
    __site_user="$2"

    # Create paths for site

    # TODO: will certbot be able to use this conf with 443 or does it need
    # to be 80 first and certbot will do the details...
    # or I suppose I could just cert-only; in that case...
    # TODO: add letsencrypt paths here (see above)

    mkdir -p /etc/nginx/conf.d/sites

    cat << EOF > /etc/nginx/conf.d/sites/"${__site_url}".conf
fastcgi_cache_path ${WWWROOT_DIR}/${__site_url}/cache levels=1:2 keys_zone=${__site_url}:100m inactive=60m;

server {
    # Ports to liten on
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    # Server name to listen for
    server_name ${__site_url};
    root ${WWWROOT_DIR}/${__site_url}/public;

    # File to be used as index
    index index.php;

    # Allow per-site logs
    access_log ${WWWROOT_DIR}/${__site_url}/logs/access.log;
    error_log ${WWWROOT_DIR}/${__site_url}/logs/error.log;

    # Load configuration files for the default server block
    # exlcusions.conf, security.conf, static-files.conf,
    # fastcgi-cache.conf, ssl.conf
    include /etc/nginx/default.d/*.conf;

    location / {
    try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php$ {
    try_files \$uri =404;
    fastcgi_intercept_errors on;
    include fastcgi_params;
    fastcgi_pass ${__site_user};

    # Skip cache based on rules in fastcgi-cache.conf.
	fastcgi_cache_bypass \$skip_cache;
	fastcgi_no_cache \$skip_cache;

	# Define memory zone for caching. Should match key_zone in fastcgi_cache_path above.
	fastcgi_cache ${__site_url};

	# Define caching time.
	fastcgi_cache_valid 60m;
    }
}

# Redirect http to https
server {
	listen 80;
	listen [::]:80;
	server_name ${__site_url};

	return 301 https://${__site_url}\$request_uri;
}

# Redirect www to non-www
server {
	listen 443;
	listen [::]:443;
	server_name www.${__site_url};

	return 301 https://${__site_url}\$request_uri;
}
EOF

    nginx -t || flog_this "Error in nginx config."
    systemctl restart nginx.service
    return $?
}

fphpfpm_setup() {
    # Usage: function <SITE_URLS> <site_user>
    __site_url="$1"
    __site_user="$2"

    # Add upstream tag for PHP user
    cat << EOF >> /etc/nginx/conf.d/php-fpm.conf

# Added by ${PRGNAM}
upstream ${__site_user} {
    server unix:/run/php-fpm/${__site_user}.sock;
}
EOF

    # Update generic PHP-FPM pool with correct permissions
    cp -a /etc/php-fpm.d/www.conf /etc/php-fpm.d/www-dist.conf || \
        flog_error "Line 618"
    sed -i -e "s/^user =.*/user = ${WWW_USER}/g" \
        -e "s/^group =.*/group = ${WWW_GROUP}/g" \
        /etc/php-fpm.d/www.conf || flog_error "620"

    # Create unique FPM pool for each site for security and good health.
    cat << EOF > /etc/php-fpm.d/${__site_user}.conf
[${__site_user}]
user = ${__site_user}
group = ${WWW_GROUP}

listen = /run/php-fpm/${__site_user}.sock
listen.owner = ${__site_user}
listen.group = ${WWW_GROUP}
listen.mode = 0660

pm = dynamic
pm.max_children = 5
pm.start_servers = 1
pm.min_spare_servers = 1
pm.max_spare_servers = 1
pm.max_requests = 500

php_admin_value[error_log]=${WWWROOT_DIR}/${__site_url}/logs/debug.log
EOF
    if [ $? -ne 0 ]; then
        flog_error "Line 624"
    fi

    systemctl restart php-fpm nginx
    return $?
}

fwordpress_setup() {
    # Usage: function <SITE_URLS> <site_user>
    __site_url="$1"
    __site_user="$2"
    __wordpress_db_name="${__site_user}"
    __wordpress_db_user="${__site_user}"
    __wordpress_db_password="$(fpassword_gen)"
    printf "WP_DB_NAME = %s\nWP_DB_USER = %s\nWP_DB_PASSWORD = %s\n" \
        "$__wordpress_db_name" \
        "$__wordpress_db_user" \
        "$__wordpress_db_password"

    flog_this "Setting up wordpress for site: ${__site_url}."

    # Install the database
    mysql -u root -p"${MYSQL_ROOT_PASSWORD}" << EOF
CREATE DATABASE ${__wordpress_db_name};
CREATE USER '${__wordpress_db_user}'@localhost IDENTIFIED BY '${__wordpress_db_password}';
GRANT ALL PRIVILEGES ON ${__wordpress_db_name}.* TO '${__wordpress_db_user}'@localhost;
FLUSH PRIVILEGES;
EOF

    if [ $? -ne 0 ]; then
        flog_error "Line 661. ${__wordpress_db_name}"
    fi


    #cd ${WWWROOT_DIR}/${__site_url}/public/core || flog_error "673"
    #$WP_CLI core download || flog_error "674"
    #$WP_CLI config create --dbname="${__wordpress_db_name}" \
    #                      --dbuser="${__wordpress_db_user}" \
    #                      --dbpass="${__wordpress_db_password}" || \
    #                      flog_error "675"
    #$WP_CLI core install --url="${__site_url}" || flog_error "680"

    #cd ../
    #cp "${WWWROOT_DIR}/${__site_url}/public/core/index.php" ./index.php || \
    #    flog_error "683"
    #sed -i -e "s/\/wp-blog-header/\/core\/wp-blog/header/g" index.php \
    #    || flog_error "685"

    #cd ${WWWROOT_DIR}/${__site_url}/public/core || flog_error "688"
    #$WP_CLI option update --siteurl ${__site_url}/core || flog_error "689"

    return $?
}

###############
# FINAL STEPS #
###############

fcertbot_setup() {
    # TODO: Add certbot instructions.
    flog_this "Certbot not configured. 700."
    return $?
}

fsudo_user_setup() {
    flog_this "Setting up sudo user: ${SUDO_USER}"
    useradd "${SUDO_USER}" -p "${SUDO_USER_PASSWORD}" \
        -m -G "wheel,${WWW_GROUP}" -U
    return $?
}

fpost_install() {

    # Restrict remote ssh access to non-root users via ssh-keys
    sed -i -e 's/^PermitRootLogin.*/PermitRootLogin no/g' \
        -e 's/^PasswordAuthentication.*/PasswordAuthentication no/g' \
        -e 's/^\#PubkeyAuthentication.*/PubkeyAuthentication yes/g' \
        /etc/ssh/sshd_config || flog_error "718"

    systemctl restart sshd.service

    if [ "$AUTO_UPDATE" = "yes" ]; then
        # Enable automatic updates
        dnf install -y dnf-automatic

        sed -i -e 's/^apply_updates.*/apply_updates = yes/g' \
            -e 's/^emit_via.*/emit_via = motd,stdio/g' \
            /etc/dnf/automatic.conf || flog_error "729"

        systemctl enable --now dnf-automatic.timer
    fi

    # TODO: Edit the motd for first user login with details about:
    #       - file structure
    #       - certbot instructions
    #       - any usernames or passwords
    #       - autoupdating
    #       - other general instructions / updating
    #       - future functionality adding additional sites
}


# TODO: case conditionals for passed arguments
# TODO: loop the functions with multiple domains
# TODO: create a function or sed that creates site_user from SITE_URLS

flog_this "$SITE_URLS"
flog_this "$SUDO_USER"
flog_this "$SUDO_USER_PASSWORD"
flog_this "$MYSQL_ROOT_PASSWORD"
flog_this "$PHP_VERSION"
flog_this "$AUTO_UPDATE"

flog_this "$WWW_USER"
flog_this "$WWW_GROUP"
flog_this "$SITE_GROUP"

flog_this "$WWWROOT_DIR"
flog_this "$WP_CLI"

flog_this "$LOG_PATH"
flog_this "$INSTALL_LOG"

main() {
flog_this "Beginning global setup."

# global setup
for __global in fcheck_distro \
    fel8_setup \
    ffail2ban_setup \
    fmysql_setup \
    fnginx_setup \
    fphp_setup; do

    flog_this "Checking ${__global}..."
    "${__global}"
    if [ $? -eq 0 ]; then
        flog_this "${__global} success."
    else
        flog_error "${__global} failed."
    fi

done || flog_error "752"

flog_this "Finished global setup."

flog_this "Beginning site-specific setup."
# local setup
# Create array from site_url domains
__domains=$(echo "$SITE_URLS" | sed -e 's/ //g') || flog_error "Line 755."
__old_ifs="$IFS"
IFS=,
set -- $__domains || flog_error "773"
while [ $# -gt 0 ]; do
    __site="$1"
    __user="$(echo "$__site" | sed -e 's/\./_/g')" || flog_error "Line 761."

    for __local in fsite_user_setup \
        fsite_setup \
        fphpfpm_setup \
        fwordpress_setup; do

            flog_this "Checking ${__local}..."
            "${__local}" "${__site}" "${__user}"
            if [ $? -eq 0 ]; then
                flog_this "${__local} success."
            else
                flog_error "${__local} failed."
            fi
    done
    shift
done || flog_error "774"
IFS="$__old_ifs"
flog_this "Finished site-specific setup."

flog_this "Beginning post-install cleanup."
#post-install cleanup
for __postinstall in fcertbot_setup \
    fsudo_user_setup \
    fpost_install; do

    flog_this "Checking ${__postinstall}..."
    "${__postinstall}"
    if [ $? -eq 0 ]; then
        flog_this "${__postinstall} success."
    else
        flog_error "${__postinstall} failed."
    fi
done
flog_this "Finished post-install cleanup."
reboot
}

main >> "$INSTALL_LOG"
