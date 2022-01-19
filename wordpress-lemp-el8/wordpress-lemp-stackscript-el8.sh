#!/usr/bin/env sh

## StackScript for installing a LEMP stack on el8-compatible distros
## for one or more Wordpress installs. 

## StackScript User Defined Fields
#udf_sudo_user
# <UDF name="udf_sudo_user" label="'sudo' user for system management. Be sure to have at least one ssh key assigned to the Linode." default="" example="" />
# udf_sudo_user_password
# <UDF name="udf_sudo_user_password" label="Password for sudo user." default="" example="" />
# udf_site_urls
# <UDF name="udf_site_urls" label="Domain name(s) separated by a single space for Wordpress site." default="" example="example.com sample-site.com yourdomain.org" />
# udf_mysql_root_password
# <UDF name="udf_mysql_root_password" label="MariaDB Root Password. Save and keep in a secure location. " default="" example="" />
# udf_php_version
# <UDF name="udf_php_version" label="Choose PHP version for Wordpress." default="" example="" oneof="7.4,8.0,8.1" />
# udf_auto_update
# <UDF name="udf_auto_update" label="Auto update the distro?" default="" example="" oneof="Yes,No" />



PRGNAM="wordpress-stackscript-el"
VERSION="0.4"

site_urls="${udf_site_urls}"
sudo_user="${udf_sudo_user}"
sudo_user_password="${udf_sudo_user_password}"
mysql_root_password="${udf_mysql_root_password}"
php_version="${udf_php_version}"
auto_update="${udf_php_version:-}"

linode_id="${LINODE_ID}"
linode_ram="${LINODE_RAM}"
linode_datacenterid="${LINODE_DATACENTERID}"

www_user="${www_user:-nginx}"
www_group="${www_group:-nginx}"

wwwroot_path="${wwwroot_path:-/var/www}"
log_path="${log_path:-/var/log}"
install_log="${log_path}/${PRGNAM}-install.log"

# TODO: function to make random passwords.
# TODO: regex or function to make site_user from site_url

flog_this() {
    printf "[%s]\n%s\n\n" "$(date)" "$1"
    return $?
}

flog_error() {
    printf "\u001b[31;1m[%s]\nERROR: %s\n\n" "$(date)" "$1"
    return $?
}

fpassword_gen() {
    __retval="$(curl -s 'https://www.random.org/strings/?num=1&len=16&digits=on&upperalpha=on&loweralpha=on&unique=on&format=plain&rnd=new' 2>/dev/null)"
    prtinf "%s" "$__retval"
}

fcheck_distro() {
    if [ -r /etc/rhel-release ]; then
        __version="$(awk -F= '/^VERSION_ID/{print $2}' /etc/os-release)"

        case "$__version" in
        "8*")
            return 0 ;;
        *)
            flog_this "Error. Script supports el8.* ${__version} detected."
            return 1 ;;
        esac
    else
        flog_this "Error. Script supports el8.* ${__version} detected."
        return 1 ;;
    fi
}

################
# GLOBAL SETUP #
################

fel8_setup() {

    # Initial update
    /usr/bin/dnf update -y || \
        logThis "Error. 'dnf' not found."; return 1 

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
    case "$php_version" in
        8*)
            /usr/bin/dnf install -y dnf-utils \
                http://rpms.remirepo.net/enterprise/remi-release-8.rpm

            /usr/bin/dnf module reset php -y
            /usr/bin/dnf module enable php:remi-${php_version} -y
            ;;
        7.4)
            /usr/bin/dnf module reset php -y
            /usr/bin/dnf module enable php:${php_version} -y
            ;;
    esac

    # Install everything
    /usr/bin/dnf install -y curl nginx mariadb-server php php-fpm \
        php-mysqlnd php-opcache php-gd php-curl php-cli php-json php-xml 


    /usr/bin/systemctl enable nginx mariadb php-fpm fail2ban
    /usr/bin/systemctl start nginx mariadb php-fpm fail2ban

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

    return $?
}

fnginx_setup() {

    mv /etc/nginx.conf /etc/nginx-dist.conf
    cat << EOF > /etc/nginx.conf
# Modified by wodpress-lemp-el8 stackscript
# For more information on configuration, see:
#   * Official English Documentation: http://nginx.org/en/docs/
#   * Official Russian Documentation: http://nginx.org/ru/docs/

user nginx;
worker_processes auto;
worker_rlimit_nofile 8192;
error_log /var/log/nginx/error.log warn;
access_log /var/log/nginx/access.log;
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

    access_log  /var/log/nginx/access.log  main;

    sendfile              on;
    tcp_nopush            on;
    tcp_nodelay           on;
    send_timeout          30;
    keepalive_timeout     15;
    client_body_timeout   30;
    client_header_timeout 30;
    types_hash_max_size 2048;
    
    # Set the maximum allowed size of client request body. This should be set
    # to the value of files sizes you wish to upload to the WordPress Media Library.
    # You may also need to change the values 'upload_max_filesize' and 'post_max_size' within
    # your php.ini for the changes to apply.

    client_max_body_size 64m;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Some WP plugins that push large amounts of data via cookies
	# can cause 500 HTTP errors if these values aren't increased.
	fastcgi_buffers 16 16k;
	fastcgi_buffer_size 32k;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;

    # Sites
    include /etc/nginx/conf.d/sites/*.conf

    server {
        listen       80 default_server;
        listen       [::]:80 default_server;
        server_name  _;
        root         /usr/share/nginx/html;

        # Load configuration files for the default server block.
        include /etc/nginx/default.d/*.conf;

        location / {
        }

        location ~ \.php$ {
        try_files \$uri =404;
        fastcgi_intercept_errors on;
        fastcgi_index  index.php;
        include        fastcgi_params;
        fastcgi_param  SCRIPT_FILENAME  \$document_root\$fastcgi_script_name;
        fastcgi_pass   php-fpm;

        error_page 404 /404.html;
            location = /40x.html {
        }

        error_page 500 502 503 504 /50x.html;
            location = /50x.html {
        }
    }

# Settings for a TLS enabled server.
#
#    server {
#        listen       443 ssl http2 default_server;
#        listen       [::]:443 ssl http2 default_server;
#        server_name  _;
#        root         /usr/share/nginx/html;
#
#        ssl_certificate "/etc/pki/nginx/server.crt";
#        ssl_certificate_key "/etc/pki/nginx/private/server.key";
#        ssl_session_cache shared:SSL:1m;
#        ssl_session_timeout  10m;
#        ssl_ciphers PROFILE=SYSTEM;
#        ssl_prefer_server_ciphers on;
#
#        # Load configuration files for the default server block.
#        include /etc/nginx/default.d/*.conf;
#
#        location / {
#        }
#
#        error_page 404 /404.html;
#            location = /40x.html {
#        }
#
#        error_page 500 502 503 504 /50x.html;
#            location = /50x.html {
#        }
#    }

}
EOF

    cat << EOF > /etc/nginx/conf.d/gzip
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

    mv /etc/nginx/default.d/php.conf /etc/nginx/default.d/php.conf.disabled

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
if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in|edd_items_in_cart|woocommerce_items_in_cart") {
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
	try_files $uri $uri/ /index.php?$args;
	access_log off;
	log_not_found off;
}
EOF

    nginx -t || flog_this "Error in nginx config."
    systemctl restart nginx.service

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

######################
# SITE SPECFIC SETUP #
######################

fsite_user_setup(){
    __site_url="$1"
    __site_user="$2"

    useradd ${__site_user} -m -d ${wwwroot_path}/${__site_url} || \
        flog_this "Error creating site user for ${__site_user}".

    # TODO:: is this the correct place to do this?
    mkdir -p ${wwwroot_path}/${__site_url}/{public,cache,logs}
    chown -R ${__site_user}:${__site_user} ${wwwroot_path}/${__site_url} || \
         flog_this "Error chowning user home for ${__site_user}".

    return $?
}

fsite_setup() {
    # Usage: function <site_urls> <site_user>
    __site_url="$1"
    __site_user="$2"

    # Create paths for site

    # TODO: will certbot be able to use this conf with 443 or does it need
    # to be 80 first and certbot will do the details...
    # or I suppose I could just cert-only; in that case...
    # TODO: add letsencrypt paths here (see above)

    mkdir -p /etc/nginx/conf.d/sites

    cat << EOF > /etc/nginx/conf.d/sites/${__site_url}.conf
fastcgi_cache_path ${wwwroot_path}/${__site_url}/cache levels=1:2 keys_zone=${__site_url}:100m inactive=60m;

server {
    listen 80;

    server_name ${__site_url} www.${__site_url};
    root ${wwwroot_path}/${__site_url}/public;
    index index.php;

    # Allow per-site logs
    access_log ${wwwroot_path}/${__site_url}/logs/access.log;
    error_log ${wwwroot_path}/${__site_url}/logs/error.log;

    # Default server block rules
    include etc/nginx/default.d/*.conf;

    location / {
    try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php$ {
    try_files \$uri =404;
    include fastcgi_params;
    fastcgi_pass unix:/run/php-fpm/${__site_user}.sock;
    
    # Skip cache based on rules in server/fastcgi-cache.conf.
	fastcgi_cache_bypass \$skip_cache;
	fastcgi_no_cache \$skip_cache;

	# Define memory zone for caching. Should match key_zone in fastcgi_cache_path above.
	fastcgi_cache ${__site_url};

	# Define caching time.
	fastcgi_cache_valid 60m;
    }

# Redirect http to https
#server {
#	listen 80;
#	listen [::]:80;
#	server_name ${__site_url} www.${__site_url};
#
#	return 301 https://${__site_url}\$request_uri;
#}

# Redirect www to non-www
#server {
#	listen 443;
#	listen [::]:443;
#	server_name www.${__site_url};
#
#	return 301 https://${__site_url}\$request_uri;
#}
EOF
    
    nginx -t || flog_this "Error in nginx config."
    systemctl restart nginx.service
    return $?
}

fphpfpm_setup() {
    # Usage: function <site_urls> <site_user>
    __site_url="$1"
    __site_user="$2"

    # Update generic PHP-FPM pool with correct permissions
    cp -a /etc/php-fpm.d/www.conf /etc/php-fpm.d/www-dist.conf
    sed -i -e "s/^user =.*/user = ${www_user}/g" \
        -e "s/^group =.*/group = ${www_group}/g" \
        /etc/php-fpm.d/www.conf

    # Create unique FPM pool for each site for security and good health.
    cat << EOF > /etc/php-fpm.d/${__site_user}.conf
[${__site_user}]
user = ${__site_user}
group = ${__site_user}

listen = /run/php-fpm/php${php_version}-${__site_user}.sock
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

fwordpress_setup() {
    # Usage: function <site_urls> <site_user>
    __site_url="$1"
    __site_user="$2"
    __wordpress_db_name="${wordpress_db_name:-}"
    __wordpress_db_user="${wordpress_db_user:-}"
    __wordpress_db_password="${wordpress_db_password:-}"

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

###############
# FINAL STEPS #
###############

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
# TODO: create a function or sed that creates site_user from site_urls


# global setup
fcheck_distro || exit 1
fel8_setup || exit 1
ffail2ban_setup
fmysql_setup
fnginx_setup
fphp_setup

# site specific setup
# set --
# set site_url to posix array
while [ $# -gt 0 ]; do
    site="$1"
    site_user="$(echo ${site} | sed 's/./_/g')"

fsite_user_setup "$site" "$site_user"
fsite_setup "$site" "$site_user"
fphpfpm_setup "$site" "$site_user"
fwordpress_setup "$site" "$site_user"
done

# post-install cleanup
fcertbot_setup
fsudo_user_setup
fpost_install

exit 0
