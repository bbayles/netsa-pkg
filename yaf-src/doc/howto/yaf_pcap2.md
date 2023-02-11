YAF PCAP Export Features      {#yaf_pcap2}
===========================

This tutorial will explain how
**yaf** can create rolling PCAP files and indexes to quickly find a flow
within the PCAP repository.
The [previous tutorial](yaf_pcap.html) described how to use **yaf**
to index PCAP files and create PCAPs using flow information.

* [Overview](#yp2_overview)
* [Setup](#yp2_setup)
* [First Approach](#yp2_first)
* [Second Approach](#yp2_second)

Overview {#yp2_overview}
===========

In many environments the capturing of PCAP and flow are decoupled and
the analysis that occurs with flow data often requires further examination
with PCAP.  In many cases, analysts have developed custom scripts to
search PCAP files for a particular flow.  This can be difficult when a flow
spans multiple PCAP files and it is hard to determine which PCAP files
they should be analyzing.

**yaf** can capture and write rolling PCAP files as well as generate the
flow data and provide an index (using flow characteristics) into the
PCAP data for quick and easy retrieval of a particular stream.

There are two approaches for indexing the PCAP files that **yaf** is
creating.  Both will be discussed here.  Using the first approach,
**yaf** will write one line to the pcap-meta-file for each FLOW that
is contained in a PCAP file.  For example, if a flow spans three
PCAP files, the pcap-meta-file will contain 3 rows for the
flow.  The second approach configures **yaf** to write one line in
the pcap-meta-file for each PCAP.  This requires more storage
up front, but provides very quick retrieval of the PCAP.

This example will configure **yaf** to export to a rwflowpack (SiLK) instance
that will create a local repository of flow data.  This tutorial does not
provide details on installing and configuring SiLK, see
[this page](yaf_silk.html) for more details.

SETUP        {#yp2_setup}
==========

Create a file directory to store the PCAP data:

    $ mkdir /data/pcap

Create a directory for the flow repository and logging:

    $ mkdir /data/flow
    $ mkdir /var/log/rwflowpack

Create a sensor configuration file for rwflowpack
([sensor.conf](https://tools.netsa.cert.org/silk/sensor.conf.html)):

    probe S0 ipfix
          protocol tcp
          listen-on-port 18001
    end probe

    sensor S0
           ipfix-probes S0
           internal-ipblock 192.168.1.0/24
           external-ipblock remainder
    end sensor

Additionally, you will need to create a SiLK site configuration file
([silk.conf](https://tools.netsa.cert.org/silk/silk.conf.html)).  For
this example, the one located in the SiLK tarball in ``site/twoway/silk.conf``
should suffice.

Start rwflowpack:

    /usr/local/sbin/rwflowpack --sensor-conf=/data/flow/sensor.conf \
       			       --root-dir=/data/flow \
    			       --log-directory=/var/log/rwflowpack \
    			       --site-config=/data/flow/silk.conf \
    			       --pack-interfaces

Confirm rwflowpack is running and is listening on port 18001:

    $ netstat -an | grep 18001
    tcp4       0      0  *.18001                *.*                    LISTEN


First Approach         {#yp2_first}
====================

This first approach will demonstrate how to use the
rolling PCAP option in **yaf** with the pcap-meta-file option
to write one line to the given file for each **FLOW** that is
contained in a PCAP File.  For example, if a flow spans three
PCAP files, the pcap-meta-file will contain 3 rows for the
flow.  The **yafMeta2Pcap** tool will be used to query the
pcap-meta-files for a particular flow and provide the file
names of the PCAP files that contain the flow.  **yaf** will
then be run again over the particular PCAP files that contain
the flow, and **yafMeta2Pcap** will create the PCAP file
for the flow.  For a slightly quicker process,
jump to the [second approach](#yp2_second).

Start **yaf**:

    yaf --in eth0 --live pcap \
        --out localhost \
        --ipfix tcp --ipfix-port 18001 \
        --applabel --max-payload=500 \
        --silk \
        --pcap /data/pcap/yaf_pcap \
        --pcap-meta-file /data/yaf_pcap_meta --pcap-timer=60 \
	--max-pcap=500 \
        -d --log=/var/log/yaf.log --pidfile=/var/log/yaf.pid

By using the above options, **yaf** will create rolling PCAP files that will
rotate every 60 seconds (or 500MB) and write index information
to the pcap-meta-file.  The default maximum file size for PCAP files is 25 MB.
By default, **yaf** will rotate PCAP
files every 5 minutes or when the file reaches 25 MB. Both the size
and time are used to determine when a PCAP file should be rotated.
If you prefer to only rotate on time, set *--max-pcap* to something
very large.  If you prefer to only rotate when a file reaches a
particular size, set *--pcap-timer* to a high value.
**yaf** will "lock" the files until the
time has expired or the file limit is reached, meaning that **yaf**
will add ".lock" to the end of the filename until it has finished
writing to it.  The pcap-meta-file will rotate before the file reaches
2 GB.

For this example, we will do a few SiLK queries to pick a flow
we want to view the PCAP for.
[rwfilter](https://tools.netsa.cert.org/silk/rwfilter.html) is the most
import analysis tool included with the SiLK tools.  **rwfilter** is an
application for querying the data repository for flow records that satisfy
a set of filtering options.  The SiLK tools are intended to be combined
to perform a particular task.  The analysis performed below will also
use [rwstats](https://tools.netsa.cert.org/silk/rwstats.html),
[rwcut](https://tools.netsa.cert.org/silk/rwcut.html), and
[rwsilk2ipfix](https://tools.netsa.cert.org/silk/rwsilk2ipfix.html).
**rwstats** is used to summarize and sort SiLK flow records.  **rwcut**
is used to print the attributes of SiLK flow records in a delimited,
columnar, human-readable format.  **rwsilk2ipfix** convers a stream
of SiLK flow records to IPFIX format.

To use the SiLK command line tools, set the **SILK_DATA_ROOTDIR** environment
variable to your flow repository:

    $ export SILK_DATA_ROOTDIR=/data/flow

    $ rwstats --fields=29 --top --count=20
    INPUT: 395 Records for 5 Bins and 395 Total Records
    OUTPUT: Top 20 Bins by Records
    appli|   Records|  %Records|   cumul_%|
        0|       160| 40.506329| 40.506329|
      443|       124| 31.392405| 71.898734|
       80|        77| 19.493671| 91.392405|
       53|        30|  7.594937| 98.987342|
      137|         4|  1.012658|100.000000|

The above query shows what application protocols are running on my network.
Let's choose one of the unknown protocols (label 0):

    $ rwfilter --pass-destination=stdout \
      	       --application=0 --type=all \
	       --max-pass-records=2 \
	       | rwcut --fields=1,2,3,4,5,6,7,9,13,14
                sIP|            dIP|sPort|dPort|pro|   packets|     bytes|\
		                  sTime|   in|  out|
        10.20.11.51|    10.64.22.15|61416| 8080|  6|         3|       156|\
		2014/01/29T15:02:39.025|    0|    0|
        10.64.22.15|    10.20.11.51| 8080|61416|  6|         2|       104|\
		2014/01/29T15:02:39.026|    0|    0|

Now we have all the information we need to find the PCAP for this flow.  The
following command will query the data for one particular flow and
**rwsilk2ipfix** will convert the SiLK flow record to IPFIX.
**getFlowKeyHash** takes IPFIX as input, by default, and prints the 5-tuple,
vlan, flow key hash, and start time in milliseconds to stdout.

    $ rwfilter --pass-destination=stdout \
      	       --application=0 --type=all \
	       --max-pass-records=1 \
	       | rwsilk2ipfix | getFlowKeyHash
                sIP|            dIP|sPort|dPort|pro| vlan|      hash|                  ms
        10.20.11.51|    10.64.22.15|61416| 8080|  6|    0|4022100716|       1391007759025

    FILE PATH: 025/4022100716-201412915239_0.pcap

Instead of performing the previous command and piping the output of
**rwfilter** to **rwsilk2ipfix** to **getFlowKeyHash**, we can manually type
the information on the command line to **getFlowKeyHash**:

    $ getFlowKeyHash -s 10.20.11.51 \
      		     -d 10.64.22.15 \
		     -S 61416 -D 8080 -p 6 \
    		     -y 2014-01-29 -t 15:02:39.025
                sIP|            dIP|sPort|dPort|pro| vlan|      hash|                  ms
        10.20.11.51|    10.64.22.15|61416| 8080|  6|    0|4022100716|       1391007759025

    FILE PATH: 025/4022100716-201412915239_0.pcap

Now we can provide the information to **yafMeta2Pcap**.
You can see that we provided a glob pattern  of the pcap-meta-files that **yaf**
produced.  Alternatively, you could
provide a text file that contains a list of the names of the pcap-meta-files
(see the [second approach](#yp2_second) for an example).
If an output file is not provided to **yafMeta2Pcap**, the tool simply returns
the name of the PCAP file
that contains the flow we are interested in.
If our flow had been a long flow, and spanned
multiple PCAP files, the output of **yafMeta2Pcap** would have been
all of the file names that contain the flow.

    $ yafMeta2Pcap -f "/tmp/yaf_pcap_meta*" \
    	       -h 4022100716 \
    	       -t 1391007759025
    /data/pcap/yaf_pcap20140129150236_00000.pcap

If we provide an output file, **yafMeta2Pcap** will create the PCAP
file for the flow by running a **yaf** process that will only create
the PCAP file for the flow using the hash and start time.  The following
examples provides an example of combining all the tools to generate
a single PCAP file.

    $ rwfilter --pass-destination=stdout \
               --application=0 --type=all \
               --max-pass-records=1 \
               | rwsilk2ipfix | getFlowKeyHash -I |
	       yafMeta2Pcap -f "/tmp/yaf_pcap_meta*" \
	       -o /tmp/mypcap.pcap

    Found 5 packets that match criteria.

    $ capinfos -c /tmp/mypcap.pcap
    File name:           /tmp/mypcap.pcap
    Number of packets:   5

The second example assumes that **yaf** was installed in your $PATH.
If **yaf** was installed in a non-standard place, you can use the
*--yaf-program* option to specify the correct location of **yaf**.

Second Approach {#yp2_second}
================

The alternate method is to run **yaf** with the ``--index-pcap`` option to write
one line for each packet into the pcap-meta-file. The **rwfilter** and
**getFlowKeyHash** steps are the same as above.  Alternatively, you could
pipe the output of **rwfilter** to **rwsilk2ipfix** to **getFlowKeyHash**.

    $ yaf --in en2 --live pcap \
          --out localhost --ipfix tcp --ipfix-port 18001 \
          --applabel --max-payload=500 --silk \
          --pcap /tmp/pcap/yaf_pcap \
          --pcap-meta-file /tmp/yaf_pcap_meta \
          --pcap-timer=60 --index-pcap \
          -d --log=/var/log/yaf.log --pidfile=/var/log/yaf.pid

    $ rwfilter --pass-destination=stdout \
      	   --application=0 \
    	   --start-date=2014/01/29:16 \
    	   --type=all --max-pass-records=2 \
    	   | rwcut --fields=1,2,3,4,5,6,7,9,13,14
                sIP|            dIP|sPort|dPort|pro|   packets|     bytes|\
		                  sTime|   in|  out|
        10.20.11.51|    10.64.22.15|62024| 8080|  6|         2|        92|\
		2014/01/29T16:32:44.301|    0|    0|
        10.64.22.15|    10.20.11.51| 8080|62024|  6|         2|       104|\
		2014/01/29T16:32:44.301|    0|    0|

    $ getFlowKeyHash -s 10.20.11.51 -d 10.64.22.15 \
      		     -o 62024 -r 8080 -p 6 \
		     -y 2014-01-29 -t 16:32:44.301
                sIP|            dIP|sPort|dPort|pro| vlan|      hash|                  ms
        10.20.11.51|    10.64.22.15|62024| 8080|  6|    0|4061946604|       1391013164301

    FILE PATH: 301/4061946604-2014129163244_0.pcap

Now we can use the **yafMeta2Pcap** and the pcap-meta-files
to get the PCAP we are looking for.  Unlike the first example,
where a glob pattern is provided to *--pcap-meta-file*, this example
creates a list of all the meta files.

    $ ls -d -rt -1 /tmp/yaf_pcap_meta* > /tmp/meta-list.txt

    $ yafMeta2Pcap -m /tmp/meta-list.txt -t 1391013164301 \
      		   -h 4061946604 -o /tmp/mypcap.pcap -y
    Found 4 packets that match criteria.

    $ capinfos -c /tmp/mypcap.pcap
    File name:           /tmp/mypcap.pcap
    Number of packets:   4

This tutorial has shown two different ways of using **yaf** to capture
full PCAP and index it via flow data.  The second approach has
a few less steps but stores a line in the pcap-meta-file for
each packet as opposed to the first approach that writes a line for each
flow, filename unique pair.  The second approach creates larger
pcap-meta-files and requires more frequent writes to the pcap-meta-files.








