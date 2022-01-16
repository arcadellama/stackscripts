#!/usr/bin/env sh

## StackScript User Defined Fields

# <UDF name="udf_linode_username" label="Login username for this Linode instance, with sudo access for system management." default="" example="linus" />

# <UDF name="udf_linode_password" label="A unique login password for this Linode instance, with sudo access for system management." default="" example="t0rva1d1s" />

# <UDF name="udf_site_url" label="Domain name for Wordpress site." default="your-domainname.com" example="sample-site.com" />

# <UDF name="udf_mysql_root_password" label="MariaDB Root Password. " default="" example="" />

# <UDF name="udf_wordpress_db_name" label="Database name for Wordpress in MariaDB. " default="wordpress_db" example="wordpress_db" />

# <UDF name="udf_wordpress_db_user" label="Username for Wordpress database in MariaDB. " default="wp_user1" example="wp_user1" />

# <UDF name="udf_wordpress_db_password" label="Password for Wordpress database in MariaDB. " default="" example="" />

stackscript_name="wordpress-lemp"

linode_username="${udf_linode_username}"
linode_password="${udf_linode_password}"
site_url="${udf_site_url}"
mysql_root_password="${udf_mysql_root_password}"
wordpress_db_name="${udf_wordpress_db_name}"
wordpress_db_user="${udf_wordpress_db_user}"
wordpress_db_password="${udf_wordpress_db_password}"

linode_id="${LINODE_ID}"
linode_ram="${LINODE_RAM}"
linode_datacenterid="${LINODE_DATACENTERID}"

virtualhost_path="${virtualhost_path:-/usr/local/www}"
log_path="${log_path:-/var/log}"

dnf_setup() {
    printf "%s: Updating system with DNF...\n" "$(date)"

    /usr/bin/dnf update -y

    /usr/bin/firewall-cmd --permanent --add-service=http --add-service=ssh
    /usr/bin/firewall-cmd --reload

    /usr/bin/dnf config-manager --set-enabled powertools
    /usr/bin/dnf module reset php -y
    /usr/bin/dnf module enable php:7.4 -y

    /usr/bin/dnf install -y wget nginx mariadb-server php php-fpm php-mysqlnd php-opcache php-gd php-curl php-cli php-json php-xml 

    /usr/bin/dnf install -y epel-release
    /usr/bin/dnf update -y
    /usr/bin/dnf install -y fail2ban-all

    /usr/bin/systemctl enable nginx mariadb php-fpm fail2ban
    /usr/bin/systemctl start nginx mariadb php-fpm fail2ban
    return $?
}

mysql_setup(){
    printf "%s: Setting up mysql...\n" "$(date)"
    # Secure the mysql installation
    mysql --user=root <<EOF
      UPDATE mysql.user SET Password=PASSWORD('${mysql_root_password}') WHERE User='root';
      DELETE FROM mysql.user WHERE User='';
      DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
      DROP DATABASE IF EXISTS test;
      DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
      FLUSH PRIVILEGES;
EOF
    # Install the database
    mysql --user="root" --password="${mysql_root_password}" <<EOF
      CREATE DATABASE ${wordpress_db_name};
      CREATE USER ${wordpress_db_user}@localhost IDENTIFIED BY '${wordpress_db_password}';
      GRANT ALL ON ${wordpress_db_name}.* TO ${wordpress_db_user}@localhost;
      FLUSH PRIVILEGES;
EOF
    nginx -t || printf "Error in nginx config."; exit 1
    systemctl restart nginx.service
    return $?
}

nginx_setup() {
    printf "%s: Setting up nginx...\n" "$(date)"
    if [ ! -d "$virtualhost_path/$site_url" ]; then
        mkdir -p "$virtualhost_path/$site_url"
    fi

    cat << EOF > /etc/nginx/conf.d/${site_url}.conf
server {
listen 80;

server_name ${site_url} www.${site_url};
root ${virtualhost_path}/${site_url};
index index.php index.html index.htm;

location / {
try_files \$uri \$uri/ /index.php?\$args;
}

location = /favicon.ico {
log_not_found off;
access_log off;
}

location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
expires max;
log_not_found off;
}

location = /robots.txt {
allow all;
log_not_found off;
access_log off;
}

location ~ \.php$ {
include /etc/nginx/fastcgi_params;
fastcgi_pass unix:/run/php-fpm/www.sock;
fastcgi_index index.php;
fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
}
}
EOF
    return $?
}

php_setup() {
    printf "%s: Setting up PHP...\n" "$(date)"

    cp -a /etc/php.ini /etc/php-dist.ini
    sed -i -e 's/^post_max_size.*/post_max_size = 64M/g' -e 's/^memory_limit.*/memory_limit = 256M/g' -e 's/^max_execution_time.*/max_execution_time = 300/g' -e 's/upload_max_filesize.*/upload_max_filesize = 32M/g' -e 's/^;date.timezone.*/date.timezone = America\/Chicago/g' /etc/php.ini

    cp -a /etc/php-fpm.d/www.conf /etc/php-fpm.d/www-dist.conf
    sed -i -e 's/^user =.*/user = nginx/g' -e 's/^group =.*/group = nginx/g' /etc/php-fpm.d/www.conf

    systemctl restart php-fpm
    return $?
}

wordpress_setup() {
    printf "%s: Setting up Wordpress...\n" "$(date)"
    pushd /tmp
    # wget 
}

certbot_setup() {
    printf "%s Setting up certbot...\n" "$(date)"
}

user_setup() {
    printf "%s: Setting up user...\n" "$(date)"
    useradd -p ${linode_password} -m -G wheel,nginx -U ${linode_username}
    cp -a /root/.ssh /home/${linode_username}
    chmod 700 /home/${linode_username}/.ssh
    chmod 600 /home/${linode_username}/.ssh/*
}

post_install() {
    printf "%s: Finishing up...\n" "$(date)"
    
    # Edit sshd to prevent remote root access and restrict to
    # SSH keys, no passwords
    sed -i -e 's/^PermitRootLogin.*/PermitRootLogin no/g' \
        -e 's/^PasswordAuthentication.*/PasswordAuthentication no/g' \
        /etc/ssh/sshd_config

    systemctl restart sshd.service

    # Edit the motd for user login
}

if [ -x /usr/bin/dnf ]; then
    dnf_setup >> "$log_path/$stackscript_name"
else
    printf "Error. DNF not found." >> "$log_path/$stackscript_name"
    exit 1
fi

touch "$log_path/$stackscript_name"

mysql_setup >> "$log_path/$stackscript_name"
php_setup >> "$log_path/$stackscript_name"
nginx_setup >> "$log_path/$stackscript_name"
wordpress_setup >> "$log_path/$stackscript_name"
certbot_setup >> "$log_path/$stackscript_name"
user_setup >> "$log_path/$stackscript_name"
post_install >> "$log_path/$stackscript_name"

exit 0
