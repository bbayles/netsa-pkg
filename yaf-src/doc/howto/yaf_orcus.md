YAF with Orcus {#yaf_orcus}
============================

This tutorial describes how to configure **yaf** and **Orcus** to create
a passive DNS database using PostgreSQL.  It is possible to use Oracle as
the database.  For information on using Oracle with Orcus, see these
[instructions](https://tools.netsa.cert.org/orcus/doc/install.html#database-configuration-and-schema-installation).  This tutorial will also describe
how to use **super_mediator** for deduplication of DNS records and forking
IPFIX streams to [SiLK](https://tools.netsa.cert.org/silk/index.html) and
[Orcus](https://tools.netsa.cert.org/orcus/index.html).

* [Database Configuration](#yo_database)
* [Orcus Configuration](#yo_orcus)
* [Install and Configure YAF](#yo_yaf)
* [Sample Orcus Queries](#yo_view)
* [Using super_mediator](#yo_sm)

Database Configuration {#yo_database}
=======================

First step is to install PostgreSQL.  The PostgreSQL wiki provides adequate
[instructions](http://www.postgresql.org/docs/9.3/static/installation.html)
for installing from source code.  You could also use one of the following:

    $ apt-get install postgresql
    $ yum install postgresql93-server

Initialize a database storage area on disk.  PostgreSQL must have permissions
to write to the database storage area.  It is recommended to [create a
PostgreSQL user account](http://www.postgresql.org/docs/current/static/postgres-user.html). Some operating systems (e.g. Ubuntu) create a postgres user when
PostgreSQL is installed. Login as the postgres user and run the following.
You may need to add the location of initdb to your PATH. *Note that on some
operating systems the database is already initialized and the server is
started automatically after install.  The following steps may not be required
if this is the case.*

    $ mkdir /usr/local/pgsql/data
    $ mkdir /var/log/postgres
    $ chown postgres /usr/local/pgsql/data
    $ chown postgres /var/log/postgres
    $ sudo su - postgres
    $ export PATH=/usr/lib/postgresql/9.1/bin:$PATH
    $ initdb -D /usr/local/pgsql/data

Start the PostgreSQL server:

    $ pg_ctl start -D /usr/local/pgsql/data -l /var/log/postgres/postgres.log

Create the Orcus database:

    $ createdb orcus

Create roles for Orcus:

    $ psql orcus
    orcus=> create user orcus login password 'orcus';
    orcus=> create user orcususer login password 'orcus';

Change the owner of the orcus database to orcus:

    orcus=> alter database orcus owner to orcus;


Install and Configure Orcus: {#yo_orcus}
====================================

Besides glib2, glib2-devel, libpcap, libpcap-devel, python, python-devel,
libpcre, and libpcre-devel,
you will also need the following:

Libfixbuf 1.3.0 or greater is required.
Install libfixbuf before installing Orcus:

    $ tar -xvzf libfixbuf-1.7.0.tar.gz
    $ cd libfixbuf-1.7.0
    $ ./configure
    $ make
    $ make install

psycopg2 2.4.5+ is required.

    $ tar -xvzf psycopg2-2.5.2.tar.gz
    $ cd psycopg2-2.5.2
    $ python setup.py build
    $ python setup.py install

Install netsa-python.

    $ tar -xvzf netsa-python-1.4.3.tar.gz
    $ cd netsa-python-1.4.3
    $ python setup.py build
    $ python setup.py install

Install Orcus.  PKG_CONFIG_PATH should be set to the location of libfixbuf.pc:

    $ tar -xvzf orcus-1.0.3.tar.gz
    $ cd orcus-1.0.3
    $ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    $ python setup.py build
    $ python setup.py install

Install (as postgres user) the Orcus schema (provided in the Orcus tarball in sql/):

    $ psql -U orcus -d orcus -q -f sql/create-sa_orcus-1.0.0-postgres.sql
     create_rr_tables
     ------------------

If you see an error similar to:

    psql: FATAL:  Peer authentication failed for user "orcus"

You may need to modify the pg_hba.conf file: (/etc/postgresql/9.1/main/pg_hba.conf).
Change the following line from:

    local    all          postgres       peer

to:

    local    all          postgres       md5

Restart the postgresql server after making this change.


Create the Orcus configuration file (copy sample provided in tarball):

    $ cp orcus.conf.sample /etc/orcus.conf

The orcus.conf file contains settings for the
[orloader](https://tools.netsa.cert.org/orcus/doc/man-orloader.html#man-orloader), [orlookup](https://tools.netsa.cert.org/orcus/doc/man-orlookup.html), and
[orquery](https://tools.netsa.cert.org/orcus/doc/man-orquery.html).  Many
of the configuration settings are simply file directories that **orloader**
uses for polling, processing, and logging.  By default, **orloader** uses
several directories in ``/data/orcus``.  For this tutorial, we will use
the defaults.  We will need to create the following directories:

    $ mkdir /data/orcus
    $ mkdir /data/orcus/incoming
    $ mkdir /data/orcus/loading
    $ mkdir /data/orcus/error
    $ mkdir /data/orcus/archive

We will need to edit the following line with our password for the Orcus
database:

    database-uri: nsql-postgres:orcus;user=orcus;password=orcus

Additionally, if we want **orloader** to interpret IP addresses appropriately,
we need to specify our internal network:

    net-list: 192.168.0.0/16, fe80::/64

Start **orloader**:

    $ orloader --config-file /etc/orcus.conf &

Install and Configure YAF {#yo_yaf}
===============================

Install yaf:

    $ tar -xvzf yaf-2.6.0.tar.gz
    $ cd yaf-2.6.0
    $ ./configure --enable-applabel --enable-plugins
    $ make
    $ make install
    $ cp etc/yaf.conf /usr/local/etc/yaf.conf
    $ cp etc/init.d/yaf /etc/init.d/yaf
    $ chmod +x /etc/init.d/yaf

If you plan to run **yaf** as a service, Edit yaf.conf to configure rolling
IPFIX output for **orloader**.  The "filter"
part in the **YAF_EXTRAFLAGS** is optional as it will limit **yaf** to
only processing data on port 53.  You should not use a BPF filter if
you plan to export all flow data to SiLK.

    ENABLED=1
    YAF_CAP_TYPE=pcap
    YAF_CAP_IF=eth0
    YAF_IPFIX_PROTO=
    YAF_IPFIX_HOST=
    YAF_IPFIX_PORT=
    YAF_ROTATE_LOCATION=/data/yaf/yafdns
    YAF_ROTATE_TIME=60
    YAF_STATEDIR=
    YAF_PIDFILE=
    YAF_LOG=
    YAF_USER=
    YAF_EXTRAFLAGS="--applabel --max-payload=2048 \
    --plugin-name=/usr/local/lib/yaf/dpacketplugin.la --plugin-opts=53 \
    --udp-uniflow=53 --filter='port 53'"

Start yaf as a service:

    $ start yaf start

Or on the command line:

    $ yaf --in eth0 --live pcap --out /data/yaf/yafdns \
          --rotate 60 --lock --applabel --max-payload=2048 \
	  --plugin-name=/usr/local/lib/yaf/dpacketplugin.la \
	  --udp-uniflow=53 --plugin-opts=53 --filter="port 53"\
	  --log=/var/log/yaf.log --pidfile=/var/run/yaf.pid -d

If you see an error similar to:

    Starting yaf:    /usr/local/bin/yaf: error while loading shared libraries: libairframe-2.6.0.so.4: cannot open shared object file: No such file or directory
    [Failed]

Run:

    $ ldconfig

**yaf** should *NOT* be configured to write IPFIX files to the same
directory that **orloader** is polling.  **orloader** does not understand
**yaf's** locking process and will steal files from **yaf** while they
are still being written to.
[filedaemon](https://tools.netsa.cert.org/yaf2/filedaemon.html) can be used
to move files from one directory to another.

    $ mkdir /data/yaf/fail
    $ filedaemon --in '/data/yaf/yafdns*'\
       		 --nextdir=/data/orcus/incoming \
     		 --lock

Sample Queries {#yo_view}
======================

Below are some example queries to view the data:

View A records between 01-01-2010 and 09-09-2010:

    $ orquery --config-file=/etc/orcus.conf \
      	      --start-date=2010/01/01 \
	      --end-date=2010/09/09 \
	      --fields=sensor,address,type,time,direction,rr-name,rr-a\
	      --type=A

View NXDOMAIN Queries for today:

     $ oquery --config-file=/etc/orcus.conf \
       	      --fields=sensor,address,type,time,direction,q-name \
	      --type=NXDOMAIN


Use **orlookup** to find records related to yahoo:

    $ orlookup --config-file=/etc/orcus.conf \
      	       --start-date=2010/01/01 \
	       --end-date=2010/09/09 \
	       --name=*yahoo*
    date|name|address|source
    2010-02-21|com.yahoo.ns5|119.160.247.124|A
    2010-02-21|com.yahoo.ns1|68.180.131.16|A
    2010-02-21|com.yahoo.ns3|121.101.152.99|A
    2010-02-21|com.yahoo.ns2|68.142.255.16|A
    2010-02-21|com.yahoo.ns4|68.142.196.63|A


To view all A records on a particular day:

    $ orlookup --config-file=/etc/orcus.conf \
      	       --start-date=2010/02/21 \
	       --source=A

To retrieve all results from 2010 that match a particular IP address:

    $ orlookup --config-file=/etc/orcus.conf \
     	       --start-date=2010/01/01 \
	       --end-date=2010/12/31 \
	       --address=1.2.3.4

Using super_mediator {#yo_sm}
==================================

**super_mediator** can be used to with **yaf** and **Orcus** to simply
split the IPFIX input stream coming from **yaf** to **Orcus** and **SiLK**
or it can be configured to perform deduplication of DNS resource records to
reduce the data sent to and stored by Orcus.  This tutorial will provide
an example of a **super_mediator** configuration for both use cases.

Using super_mediator to split the records to Orcus and SiLK
-----------------------------------------------------------

The following configuration file for **super_mediator** listens on port 18000
for IPFIX data from **yaf**, writes the DNS data to the **Orcus** incoming
directory and the flow data to **SiLK**.  **super_mediator** is able to write
to the incoming file directory for **Orcus** as it uses a lock method that
will prevent **Orcus** from stealing the files before they are closed.  The
**LOCK** keyword is necessary in the **Orcus** exporter block (1st EXPORTER
block).  The second EXPORTER block is the **SiLK** exporter.  The STATS_ONLY
keyword is optional. If present, **super_mediator** will forward the **yaf**
process statistics records to **SiLK** so they can be logged in the
**rwflowpack** or **flowcap** log.

    COLLECTOR TCP
       PORT 18000
    COLLECTOR END

    EXPORTER FILEHANDLER
      PATH "/tmp/orcus/incoming/sm_dns"
      APPLICATION == 53
      ROTATE 600
      DPI_ONLY
      LOCK
    EXPORTER END

    EXPORTER TCP
       PORT 18001
       FLOW_ONLY
       STATS_ONLY
    EXPORTER END

The following options should be used when running **yaf**:

    $ yaf --in eth0 --live pcap \
    	  --out localhost --ipfix tcp --ipfix-port=18000 \
	  --applabel --max-payload=1024 \
	  --plugin-name=/usr/local/lib/yaf/dpacketplugin.la \
	  --plugin-opts=53 \
	  --silk \
	  --udp-uniflow=53 -v \
	  -d ---log=/var/log/yaf.log

The SiLK ``sensor.conf`` should contain a probe similar to:

    probe S1 ipfix
          protocol tcp
          listen-on-port 18001
    end probe

For more information on configuring and installing SiLK, see
[this tutorial](yaf_silk.html)

super_mediator DNS deduplication
-------------------------------------

The following **super_mediator** configuration file will enable
deduplication of DNS resource records and the records will be written
to rolling IPFIX files in the **Orcus** incoming directory.  **SiLK** export is
not configured, but could simply be added by using the above EXPORTER block
in the following configuration.


    COLLECTOR TCP
       PORT 18000
    COLLECTOR END

    EXPORTER FILEHANDLER
      PATH "/tmp/orcus/incoming/sm_dns"
      ROTATE 600
      DNS_DEDUP_ONLY
      LOCK
    EXPORTER END

    DNS_DEDUP
       MAX_HIT_COUNT 5000
       LAST_SEEN
    DNS_DEDUP END

**Note that the use of LAST_SEEN in the DNS_DEDUP block is required for
Orcus to ingest the data.**

Once again, using the **LOCK** keyword is required if **super_mediator**
is writing to the **Orcus** incoming directory.  The above **yaf** invocation
can also be used for this configuration.  If **super_mediator** is only exporting
to **Orcus**, you may consider adding ``--filter="port 53"`` to the **yaf**
invocation to filter out all non-DNS data.

**super_mediator** deduplication is configurable.  By default,
**super_mediator** will export a deduplicated resource record every 5 minutes
or when the hit count reaches 500.  These settings can be modified by
using the MAX_HIT_COUNT and FLUSH_TIME keywords in the DNS_DEDUP
block. See the [super_mediator.conf](https://tools.netsa.cert.org/super_mediator1/super_mediator.conf.html) man page
for more information.

*Note: By using **super_mediator** to remove the duplicate records, the
IP address (**address** field in **orquery**) that sent or received
the query or response will be lost.*
