fastcgi_cache_path /var/www/cache levels=1:2 keys_zone=WORDPRESS:100m inactive=6h;
fastcgi_cache_key "$scheme$request_method$host$request_uri";
fastcgi_cache_use_stale error timeout invalid_header http_500;
fastcgi_ignore_headers Cache-Control Expires Set-Cookie;
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2 ipv6only=on;
    server_name www.techbrown.com;
    index index.php index.html index.htm;
    root /var/www/html;
    client_max_body_size 0;
    
	# WordPress: deny general stuff
	location ~* ^/(?:xmlrpc\.php|wp-config\.php|wp-config-sample\.php|wp-comments-post\.php|readme\.html|license\.txt)$ {
	deny all;
	}

    location = /wp-login.php {
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/htpasswd/wpadmin;
						try_files $uri =404;
						fastcgi_split_path_info ^(.+\.php)(/.+)$;
						fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
						fastcgi_index index.php;
						include fastcgi.conf;
	}

   location ~ /wp-login.php$ {
	auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/htpasswd/wpadmin;
						try_files $uri =404;
						fastcgi_split_path_info ^(.+\.php)(/.+)$;
						fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
						fastcgi_index index.php;
						include fastcgi.conf;
    }


	location /wp-admin {
    location ~ /wp-admin/admin-ajax.php$ {
						try_files $uri =404;
						fastcgi_split_path_info ^(.+\.php)(/.+)$;
						fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
						fastcgi_index index.php;
						include fastcgi.conf;
    }
	
	location = /wp-admin/admin-ajax.php {
						try_files $uri =404;
						fastcgi_split_path_info ^(.+\.php)(/.+)$;
						fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
						fastcgi_index index.php;
						include fastcgi.conf;
    }
	
    location ~* /wp-admin/.*\.php$ {
		auth_basic "Authorization Required";
        auth_basic_user_file  /etc/nginx/htpasswd/wpadmin;
						try_files $uri =404;
						fastcgi_split_path_info ^(.+\.php)(/.+)$;
						fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
						fastcgi_index index.php;
						include fastcgi.conf;
    }
	}	
		

    location ~* \.(jpg|jpeg|png|gif|ico|css|js|pdf|woff2|woff|eot|svg|ttf)$ {
    expires 7d;
    }
	
	# favicon.ico
	location = /favicon.ico {
	log_not_found off;
	access_log off;
	}

	# robots.txt
	location = /robots.txt {
	log_not_found off;
	access_log off;
  allow all;
}
  
 # ads.txt
	location = /ads.txt {
	log_not_found off;
	access_log off;
  allow all;
}     

	# assets, media
	location ~* \.(?:css(\.map)?|js(\.map)?|cur|heic|webp|tiff|wmv)$ {
	expires 7d;
	access_log off;
	}

	# svg, fonts
	location ~* \.(?:svgz?|ttf|ttc|otf|eot|woff2?)$ {
	add_header Access-Control-Allow-Origin "*";
	expires 7d;
	access_log off;
	}
  
  # images
  location ~* .(css|gif|ico|jpeg|jpg|js|png)$ {
  expires 7d;
  log_not_found off;
  }


    location /php.ini {
    deny all;
    }

    location ~ \.user\.ini$ {
    deny all;
    }

    location /user.ini {
    deny all;
    }
    
    ssl_certificate /etc/letsencrypt/live/techbrown.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/techbrown.com/privkey.pem;  
	
	  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    ssl_session_timeout 20m;
    ssl_session_cache shared:SSL:20m;
    ssl_session_tickets off;

	# Mozilla Old configuration
	ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
  ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
	ssl_prefer_server_ciphers on;

	# Diffie-Hellman parameter for DHE ciphersuites
	ssl_dhparam /etc/nginx/dhparam.pem;

	# OCSP Stapling
	ssl_stapling on;
	ssl_stapling_verify on;
	resolver 1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220 valid=60s;
	resolver_timeout 2s;

    location ~ /.well-known {
    allow all;
    root /var/www/html;
    }

    location / {
    #try_files $uri $uri/ =404;
    try_files $uri $uri/ /index.php$is_args$args;
    }
    
 
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
    root /usr/share/nginx/html;
    }

    set $skip_cache 0;
    if ($request_method = POST) {set $skip_cache 1;}
    if ($request_uri ~* "/wp-admin/|/xmlrpc.php|/wp-.*.php|index.php|sitemap(_index)?.xml") {set $skip_cache 1;}
    if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in") {set $skip_cache 1;}



   # Pass all .php files onto a php-fpm or php-cgi server
    location ~* \.php$ {
                try_files                       $uri =404;
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                include                         /etc/nginx/fastcgi_params;
                fastcgi_param                   SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
                fastcgi_index                   index.php;
                fastcgi_cache_bypass $skip_cache;
                fastcgi_no_cache $skip_cache;
                fastcgi_cache WORDPRESS;
                fastcgi_cache_valid 200 301 24h;
                add_header X-Cache $upstream_cache_status;
    }

    location ~ ([^/]*)sitemap(.*).x(m|s)l$ {
    ## this redirects sitemap.xml to /sitemap_index.xml
    rewrite ^/sitemap.xml$ /sitemap_index.xml permanent;
    ## this makes the XML sitemaps work
    rewrite ^/([a-z]+)?-?sitemap.xsl$ /index.php?xsl=$1 last;
    rewrite ^/sitemap_index.xml$ /index.php?sitemap=1 last;
    rewrite ^/([^/]+?)-sitemap([0-9]+)?.xml$ /index.php?sitemap=$1&sitemap_n=$2 last;
    }
    


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
}

server {
    listen 80;
    listen [::]:80;
    server_name techbrown.com www.techbrown.com;
    return 301 https://techbrown.com$request_uri;
}

server {
    listen 443 http2;
    listen [::]:443 http2;
    server_name techbrown.com;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
    return 301 https://www.techbrown.com$request_uri;
}
