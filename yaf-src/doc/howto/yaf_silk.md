Configuring YAF with SiLK {#yaf_silk}
============================================

This tutorial is a step-by-step guide for setting up **yaf**,
and [SiLK](https://tools.netsa.cert.org/silk/index.html) on a single machine
for standalone Flow collection and analysis.

* [Basic Install](#ys_install)
* [Configure SiLK](#ys_silk)
* [Configure YAF](#ys_yaf)
* [Run YAF](#ys_goyaf)

Install prerequisites {#ys_install}
========================

    $ yum groupinstall "Development Tools"
    $ yum install libpcap libpcap-devel pcre pcre-devel glib2-devel

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

To run **yaf** as a service:

    $ cp etc/init.d/yaf /etc/init.d/
    $ cp etc/yaf.conf /usr/local/etc/
    $ chmod +x /etc/init.d/yaf


Build [SiLK](https://tools.netsa.cert.org/silk/index.html):

    $ tar -xvzf silk-3.19.0.tar.gz
    $ cd silk-3.19.0
    $ ./configure --with-libfixbuf=/usr/local/lib/pkgconfig --enable-ipv6
    $ make
    $ make install

Setup SiLK {#ys_silk}
============

This example uses /data as the location of the SiLK repository:

    $ mkdir -p /data

The default [silk.conf](https://tools.netsa.cert.org/silk/silk.conf.html) that comes with the SiLK distribution
is typically sufficient and should be copied to the repository:

    $ cp site/twoway/silk.conf /data

To run rwflowpack as a service:

    $ cp src/rwflowpack/rwflowpack.init.d /etc/init.d/rwflowpack
    $ chmod +x /etc/init.d/rwflowpack
    $ cp src/rwflowpack/rwflowpack.conf /usr/local/etc/rwflowpack.conf

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


The [sensor.conf](https://tools.netsa.cert.org/silk/sensor.conf.html)
is required to setup the
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

Configure YAF {#ys_yaf}
============

Create a directory for the **yaf** log file:

    $ mkdir /var/log/yaf
    $ mkdir /var/log/yaf/log
    $ mkdir /var/log/yaf/run

    $ export LTDL_LIBRARY_PATH=/usr/local/lib/yaf

To configure **yaf**, edit the configuration file ``/usr/local/etc/yaf.conf``:

    ENABLED=1
    YAF_CAP_TYPE=pcap
    YAF_CAP_IF=eth0
    YAF_IPFIX_PROTO=tcp
    YAF_IPFIX_HOST=localhost
    YAF_IPFIX_PORT=18001
    YAF_STATEDIR=/var/log/yaf
    YAF_EXTRAFLAGS="--silk --applabel --max-payload=2048 --plugin-name=/usr/local/lib/yaf/dpacketplugin.la"

Start YAF {#ys_goyaf}
===================

Start YAF via service

    service yaf start

Or on the command line.  See the following 2 examples.

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

If you see an error similar to:

    Starting yaf:    /usr/local/bin/yaf: error while loading shared libraries: l\
ibairframe-2.5.0.so.4: cannot open shared object file: No such file or directory
[Failed]

Run:
    $ ldconfig

Or add ``/usr/local/lib`` to the LD_LIBRARY_PATH environment variable.

Confirm SiLK is creating flow records:

    $ rwfilter --proto=0- --type=all --pass=stdout | rwcut | head

