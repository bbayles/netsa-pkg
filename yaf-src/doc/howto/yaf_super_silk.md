Configuring YAF with super_mediator and SiLK {#yaf_sm_silk}
============================================

This tutorial is a step-by-step guide of setting up **yaf**,
[super_mediator](https://tools.netsa.cert.org/super_mediator1/index.html), and [SiLK](https://tools.netsa.cert.org/silk/index.html).

* [Overview](#yss_overview)
* [Basic Install](#yss_install)
  * [Setup MySQL Database](#yss_mysql)
* [Configure SiLK](#yss_silk)
* [Configure super_mediator](#yss_sm)
* [Run YAF](#yss_goyaf)
* [Analysis with MySQL/SiLK](#yss_analysis)

Overview {#yss_overview}
==========

Check out this [tutorial](https://tools.netsa.cert.org/super_mediator1/sm_guide.html)
for information on what super_mediator
is and what data it can produce. This particular tutorial shows how
super_mediator can insert the DPI data
produced by **yaf** into a MySQL database. super_mediator
will perform DNS deduplication on DNS resource records.
This tutorial also shows how to do a basic install of SiLK and have
**super_mediator** forward all the flows it receives to SiLK.

Install prerequisites {#yss_install}
========================
   $ yum groupinstall "Development Tools"
   $ yum install libpcap-devel pcre-devel mysql-server mysql-devel

Build [libfixbuf](https://tools.netsa.cert.org/fixbuf2/index.html):

    $ tar -xvzf libfixbuf-2.3.0.tar.gz
    $ cd libfixbuf-2.3.0
    $ ./configure
    $ make
    $ make install

Build **yaf**:

    $ tar -xvzf yaf-2.13.0.tar.gz
    $ cd yaf-2.13.0
    $ ./configure --enable-applabel --enable-plugins
    $ make
    $ make install

Build **super_mediator**:

    $ tar -xvzf super_mediator-1.8.0.tar.gz
    $ cd super_mediator-1.8.0
    $ ./configure --with-mysql
    $ make
    $ make install

Build [SiLK](https://tools.netsa.cert.org/silk/index.html):

    $ tar -xvzf silk-3.11.0.tar.gz
    $ cd silk-3.11.0
    $ ./configure --with-libfixbuf=/usr/local/lib/pkgconfig --enable-ipv6
    $ make
    $ make install

Setup the MySQL Database  {#yss_mysql}
------------------------

Setup mysqld

    $ service mysqld start

Setup a password for the root user

    $ /usr/bin/mysqladmin -u root password '<SuperSecretPassword>'

Login to the database (It will prompt you for the password you created in the
last step):

    $ mysql -u root -p

Create the database you intend to use for super_mediator:

    mysql> create database smediator;

Create a user for super_mediator to access the database:

    mysql> CREATE USER 'mediator'@'localhost' IDENTIFIED BY '<SuperSecretPassword>';

Giver permissions to user to access only the smediator database:

    mysql> GRANT ALL ON smediator.* TO mediator@'localhost';

Setup SiLK {#yss_silk}
============

We will using /data as the location of our SiLK repository:

    $ mkdir -p /data

We will be using the default silk.conf file so copy it to the repo now:

    $ cp site/twoway/silk.conf /data
    $ cp src/rwflowpack/rwflowpack.conf /usr/local/etc/rwflowpack.conf
    $ cp src/rwflowpack/rwflowpack.init.d /etc/init.d/rwflowpack
    $ chmod +x /etc/init.d/rwflowpack

To configure **rwflowpack**, edit ``/usr/local/etc/rwflowpack.conf``

    #/usr/local/etc/rwflowpack.conf
    ENABLED=1
    statedirectory=/var/lib/rwflowpack
    CREATE_DIRECTORIES=yes
    BIN_DIR=/usr/local/sbin
    SENSOR_CONFIG=/data/sensor.conf
    DATA_ROOTDIR=/data
    SITE_CONFIG=/data/silk.conf
    PACKING_LOGIC=
    INPUT_MODE=stream
    INCOMING_DIR=${statedirectory}/incoming
    ARCHIVE_DIR=${statedirectory}/archive
    FLAT_ARCHIVE=0
    ERROR_DIR=  #${statedirectory}/error
    OUTPUT_MODE=local
    SENDER_DIR=${statedirectory}/sender-incoming
    INCREMENTAL_DIR=${statedirectory}/incremental
    COMPRESSION_TYPE=
    POLLING_INTERVAL=
    FLUSH_TIMEOUT=
    FILE_CACHE_SIZE=
    FILE_LOCKING=1
    PACK_INTERFACES=0
    LOG_TYPE=syslog
    LOG_LEVEL=info
    LOG_DIR=${statedirectory}/log
    PID_DIR=${LOG_DIR}
    USER=root
    EXTRA_OPTIONS=

We will need to create the Sensor configuration file
[sensor.conf](https://tools.netsa.cert.org/silk/sensor.conf.html) to setup the
listening probe.  Change the internal-ipblocks to match your network

    probe S0 ipfix
       listen-on-port 18001
       protocol tcp
    end probe

    sensor S0
       ipfix-probes S0
       internal-ipblocks 192.168.1.0/24 10.10.10.0/24
       external-ipblocks remainder
    end sensor

Move the sensor.conf to the repository:

    $ mv sensor.conf /data

Start **rwflowpack**:

    $ service rwflowpack start

Verify that rwflowpack is listening on port 18001:

    $ netstat -vnatpl

To use the SiLK command line tools, you need to set the **SILK_DATA_ROOTDIR** variable:

    $ export SILK_DATA_ROOTDIR=/data

Setup super_mediator {#yss_sm}
=====================

Create the file directories that **super_mediator** will use to write files
that will eventually get imported into the MySQL Database.

    $ mkdir -p /data/smediator/dpi
    $ mkdir -p /data/smediator/dns

Use **super_table_creator** to create all the tables in your database:

    $ /usr/local/bin/super_table_creator --name mediator \
      	--pass=<SuperSecretPassword> --database=smediator
    $ /usr/local/bin/super_table_creator --name mediator \
      	--pass=<SuperSecretPassword> \
	--database=smediator --dns-dedup

Create your super_mediator.conf file.  One is installed by default into /usr/local/etc.  The following one will get you started:

    COLLECTOR TCP
       PORT 18000
    COLLECTOR END

    #rwflowpack
    EXPORTER TCP
       PORT 18001
       HOST localhost
       FLOW_ONLY
    EXPORTER END

    #dedup process

    EXPORTER TEXT
       PATH "/data/smediator/dns/yaf2dns"
       DELIMITER "|"
       ROTATE 1200
       DNS_DEDUP_ONLY
       LOCK
       MYSQL_USER "mediator"
       MYSQL_PASSWORD "<SuperSecretPassword>"
       MYSQL_TABLE "dns-dedup"
       MYSQL_DATABASE "smediator"
    EXPORTER END

    #dpi 2 database
    EXPORTER TEXT
       PATH "/data/smediator/dpi"
       ROTATE 1200
       MULTI_FILES
       DPI_ONLY
       LOCK
       MYSQL_USER "mediator"
       MYSQL_PASSWORD "<SuperSecretPassword>"
       MYSQL_DATABASE "smediator"
    EXPORTER END

    DNS_DEDUP
       MAX_HIT_COUNT 5000
    DNS_DEDUP END

    LOGLEVEL DEBUG

    LOG "/var/log/super_mediator.log"

    PIDFILE "/data/super_mediator.pid"

Start **super_mediator**:

    $ super_mediator -c /usr/local/etc/super_mediator.conf --daemonize

Confirm **super_mediator** is running:

    $ ps -ef | grep super

If **super_mediator** is not running, check for any errors:

    $ cat /var/log/super_mediator.log

Start YAF {#yss_goyaf}
============

    $ mkdir /var/log/yaf

    $ export LTDL_LIBRARY_PATH=/usr/local/lib/yaf

Example **yaf** command line for processing a PCAP file:

    /usr/local/bin/yaf
    --in <PCAP FILE> \
    --ipfix tcp \
    --out localhost \
    --log /var/log/yaf/yaf.log \
    --verbose \
    --silk \
    --verbose \
    --ipfix-port=18000 \
    --applabel --max-payload 2048 \
    --plugin-name=/usr/local/lib/yaf/dpacketplugin.so

Example **yaf** command line for sniffing interface eth0:

    /usr/local/bin/yaf
    --in eth0 --live pcap \
    --ipfix tcp \
    --out localhost \
    --log /var/log/yaf/yaf.log \
    --verbose \
    --silk \
    --verbose \
    --ipfix-port=18000 \
    --applabel --max-payload 2048 \
    --plugin-name=/usr/local/lib/yaf/dpacketplugin.so

Confirm Install and Sample Analysis {#yss_analysis}
====================================

Confirm MySQL database contains data:

    $ mysql -u root -p

    mysql> use smediator;

    mysql> select table_name, table_rows from information_schema.tables where table_schema = DATABASE();
    +-------------+------------+
    | table_name  | table_rows |
    +-------------+------------+
    | dhcp        |          0 |
    | dns         |      73414 |
    | flow        |      39946 |
    | ftp         |         36 |
    | http        |      77462 |
    | imap        |         78 |
    | irc         |        224 |
    | mysql       |          0 |
    | nntp        |          0 |
    | p0f         |          0 |
    | pop3        |         12 |
    | rtsp        |          0 |
    | sip         |          0 |
    | slp         |          0 |
    | smtp        |         96 |
    | ssh         |         44 |
    | tftp        |          0 |
    | tls         |      34370 |
    +-------------+------------+

Confirm SiLK is creating flow records:

    $ rwfilter --proto=0- --type=all --pass=stdout | rwcut | head

