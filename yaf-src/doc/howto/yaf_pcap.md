Indexing PCAP Files with YAF        {#yaf_pcap}
==============================

The following tutorial describes how to use **yaf**'s PCAP features.
It will discuss the various approaches to indexing PCAP and creating PCAP
for a particular flow.  This tutorial makes use of two additional
tools that are installed with **yaf**, **yafMeta2Pcap** and **getFlowKeyHash**.
The [next tutorial](yaf_pcap2.html)
 will discuss how to enable **yaf** to create a rolling
buffer of PCAPs and index the PCAPs by flows.  Both tutorials assume you
are using the most recent release of **yaf**.

* [Overview](#overview)
* [Single File Example](#single)
  * [Index with pcap-meta-file](#index1)
  * [Use getFlowKeyHash and YAF](#getkeyhash)
  * [Using a BPF Filter](#bpf)
  * [Pcap-per-flow](#pcap-per-flow)
* [Multiple File Example](#multiple)

Overview {#overview}
===========

Often analysis of very large PCAP files can be difficult due to lack of
tools for effectively reading and slicing large PCAP files.  **yaf** provides
a couple options for performing analysis over one or more large PCAP files.
Additionally, these features can be used on live traffic.  However, the
pcap-per-flow option is not recommended for networks with high data speeds.

The following tutorial uses **yaf** and the tools that are installed
with **yaf**.  It also uses [SiLK](https://tools.netsa.cert.org/silk/index.html)
for some basic flow analysis.  In addition, this example uses
[capinfos](http://www.wireshark.org/docs/man-pages/capinfos.html),
a program installed with Wireshark, that provides statistics of PCAP files.

*Note: **yaf** must be configured with application labeling in order to perform
the analysis described below.*

Single Large PCAP Example {#single}
=========================

Let's assume we have one large PCAP that we would like to analyze.
First, we could create SiLK flow data from this PCAP using
[rwipfix2silk](https://tools.netsa.cert.org/silk/rwipfix2silk.html):

    $ yaf --in /data/big.pcap --out - \
          --applabel --max-payload=1500 --silk \
          | rwipfix2silk --silk-output=/tmp/yaf2flow.rw \
          --interface-values=vlan

Note that it is important to use the ``--interface-values`` option to
**rwipfix2silk** so we can view the VLAN tags (if the PCAP contains vlans).

Alternatively, you could use [yafscii](https://tools.netsa.cert.org/yaf2/yafscii.html)
or [super_mediator](https://tools.netsa.cert.org/super_mediator1/index.html) to view
the flow data that **yaf** creates.  This tutorial uses the SiLK tools as they
provide the quickest method for filtering the flow data.

Perhaps we do some analysis on the flow data we created.
The following example uses [rwstats](https://tools.netsa.cert.org/silk/rwstats.html), a tool for summarizing SiLK flow records and sorting the results, to
view the top 20 application protocols used in the flow file:

    $ rwstats --fields=29 --top --count 20 /tmp/yaf2flow.rw
    INPUT: 64510 Records for 24 Bins and 64510 Total Records
    OUTPUT: Top 20 Bins by Records
    appli|   Records|  %Records|   cumul_%|
       53|     27302| 42.322121| 42.322121|
        0|     24383| 37.797241| 80.119361|
       80|      5675|  8.797086| 88.916447|
      443|      5416|  8.395598| 97.312045|
      137|       778|  1.206015| 98.518059|
      161|       391|  0.606108| 99.124167|
       67|       344|  0.533251| 99.657417|
       22|        42|  0.065106| 99.722524|
     2223|        30|  0.046504| 99.769028|
     5222|        24|  0.037204| 99.806232|
     5004|        21|  0.032553| 99.838785|
     5190|        18|  0.027903| 99.866687|
      143|        14|  0.021702| 99.888389|
      902|        12|  0.018602| 99.906991|
       25|        12|  0.018602| 99.925593|
     1723|        12|  0.018602| 99.944195|
      194|        12|  0.018602| 99.962796|
      110|         6|  0.009301| 99.972097|
     1863|         4|  0.006201| 99.978298|
     5050|         4|  0.006201| 99.984499|

Let us focus on the 4 records
labeled as application 5050, Yahoo Messenger.  A list
of application labels can be found on the
[applabel](https://tools.netsa.cert.org/yaf2/applabel.html) man page.

Use **rwfilter** and **rwcut** to obtain more details about the flows
labeled as 5050.  [rwfilter](https://tools.netsa.cert.org/silk/rwfilter.html)
selects SiLK flow records that satisfy a set of filtering options, while
[rwcut](https://tools.netsa.cert.org/silk/rwcut.html) prints the attributes
of the flow records in human-readable format.

    $ rwfilter --application=5050 --pass-dest=stdout /tmp/yaf2flow.rw \
      	       | rwcut --fields=1,2,3,4,5,6,7,9,13,14
                sIP|            dIP|sPort|dPort|pro|   packets|     bytes|\
		                  sTime|   in|  out|
        10.10.0.208|  98.136.48.106|50997| 5050|  6|        23|      3250|\
		2011/01/28T21:53:05.607|  900|    0|
      98.136.48.106|    10.10.0.208| 5050|50997|  6|        18|      3264|\
      		2011/01/28T21:53:05.685|  900|    0|
        10.10.0.208|   98.136.48.48|51094| 5050|  6|        29|      3730|\
		2011/01/28T21:53:26.219|  900|    0|
       98.136.48.48|    10.10.0.208| 5050|51094|  6|        24|      6284|\
       		2011/01/28T21:53:26.296|  900|    0|

**rwfilter** returns the 4 flow records, or 2 bidirectional flow (Biflow) records. I'm
interested in the first Biflow and would like to perform a deeper
analysis of this particular flow by looking at the PCAP.

There are four ways to do this in **yaf**:

1. [Index the PCAP file using the pcap-meta-file](#index1)
2. [Use getFlowKeyHash and YAF](#getkeyhash)
3. [Use a BPF Filter](#bpf)
4. [Use the pcap-per-flow option](#pcap-per-flow)

Indexing the PCAP file using the pcap-meta-file {#index1}
-----------------------------------------------

The first way is to index the PCAP file using the pcap-meta-file. In the
following example we use the ``-no-output`` option.  Alternatively, we
could write the flow data to ``/dev/null`` because we are
only interested in the pcap-meta-file.

    $ yaf --in /data/big.pcap \
          --no-output \
          --pcap-meta-file /tmp/yaf_ -v
    [2014-12-23 14:16:00] yaf starting
    [2014-12-23 14:16:00] Reading packets from /data/big.pcap
    [2014-12-23 14:16:00] Opening Pcap Meta File /tmp/yaf_20141223141600_00000.meta
    [2014-12-23 14:16:07] Processed 5921725 packets into 42096 flows:
    [2014-12-23 14:16:07]   Mean flow rate 6688.29/s.
    [2014-12-23 14:16:07]   Mean packet rate 940854.79/s.
    [2014-12-23 14:16:07]   Virtual bandwidth 3366.3978 Mbps.
    [2014-12-23 14:16:07]   Maximum flow table size 10742.
    [2014-12-23 14:16:07]   181 flush events.
    [2014-12-23 14:16:07]   19580 asymmetric/unidirectional flows detected (46.51%)
    [2014-12-23 14:16:07] YAF read 6140871 total packets
    [2014-12-23 14:16:07] Assembled 33328 fragments into 15414 packets:
    [2014-12-23 14:16:07]   Expired 552 incomplete fragmented packets. (0.01%)
    [2014-12-23 14:16:07]   Maximum fragment table size 41.
    [2014-12-23 14:16:07] Rejected 201232 packets during decode: (3.17%)
    [2014-12-23 14:16:07]   201232 due to unsupported/rejected packet type: (3.17%)
    [2014-12-23 14:16:07]     201232 unsupported/rejected Layer 3 headers. (3.17%)
    [2014-12-23 14:16:07]     196465 ARP packets. (3.10%)
    [2014-12-23 14:16:07] yaf Exported 1 stats records.
    [2014-12-23 14:16:07] yaf terminating

    $ wc -l /tmp/yaf_20141223141600_00000.meta
     5922318 /tmp/yaf_20141223141600_00000.meta

You can see that the PCAP metadata file contains at least one line for each
packet in the PCAP.  The additional lines are to speed up processing
of this file.  We will need the flow key hash and
the start time in milliseconds for the flow we are interested in,
which is provided to us by the **getFlowKeyHash** tool.  The flow key
hash is used by **yaf** as a unique identifier for a flow.  The flow
key hash is a hash of the 5-tuple (src ip, dst ip, src port, dst
port, and protocol) and the VLAN.  That's why it was important to
use the ``--interface-values`` option with **rwipfix2silk**.  If your PCAP
does not contain VLAN tags, then it is not necessary.

We could either list the flow information on the command line:

    $ getFlowKeyHash --sip4 10.10.0.208 --dip4 98.136.48.106 \
      		     --sport 50997 --dport 5050 \
    		     --protocol 6 --vlan 900 \
    		     --date 2011-01-28 --time 21:53:05.607
                sIP|            dIP|sPort|dPort|pro| vlan|      hash|                  ms
        10.10.0.208|  98.136.48.106|50997| 5050|  6|  900|2549564224|       1296251585607

    FILE PATH: 607/2549564224-201112821535_0.pcap

Or we can use **rwsilk2ipfix** with **getFlowKeyHash**.
[rwsilk2ipfix](https://tools.netsa.cert.org/silk/rwsilk2ipfix.html) converts
a stream of SiLK flow records (such as the one produced by **rwfilter**) to
IPFIX records (default input of **getFlowKeyHash**).

    $ rwfilter --application=5050 --pass-dest=stdout /tmp/yaf2flow.rw \
      	       | rwsilk2ipfix | getFlowKeyHash
                sIP|            dIP|sPort|dPort|pro| vlan|      hash|                  ms
        10.10.0.208|  98.136.48.106|50997| 5050|  6|  900|2549564224|       1296251585607
      98.136.48.106|    10.10.0.208| 5050|50997|  6|  900|1131976655|       1296251585607
        10.10.0.208|   98.136.48.48|51094| 5050|  6|  900|2538881818|       1296251606219
       98.136.48.48|    10.10.0.208| 5050|51094|  6|  900|1131976502|       1296251606219


We are interested in the "hash" and "ms" values.  The
FILE PATH will be used in the third approach.

Using the key hash, milliseconds, along with the oringal PCAP, and the PCAP
metadata file, the **yafMeta2Pcap** tool will create the PCAP we
are looking for:

    $ yafMeta2Pcap --pcap /data/big.pcap \
                   --pcap-meta-file=/tmp/yaf_20141223141600_00000.meta \
                   --out /tmp/YMSG.pcap \
                   --hash 2549564224 \
                   --time 1296251585607 -v
    Looking for hash: 2549564224 at start time: 1296251585607
    Opening PCAP Meta File: /tmp/yaf_20141223141600_00000.meta
    Opening PCAP File /data/big.pcap
    Opening output file /tmp/YMSG.pcap
    Found 41 packets that match criteria.

    $ capinfos -c /tmp/YMSG.pcap
    File name:           /tmp/YMSG.pcap
    Number of packets:   41

Alternatively, you can send the output of **getFlowKeyHash** directly to
**yafMeta2Pcap**:

    $ rwfilter --application=5050 --pass-dest=stdout /tmp/yaf2flow.rw \
      	       | rwsilk2ipfix | getFlowKeyHash -I | yafMeta2Pcap \
               --pcap /data/big.pcap --pcap-meta-file /tmp/yaf_meta_pcap.txt \
	       --out /tmp/YMSG.pcap
    Looking for hash: 2549564224 at start time: 1296251585607
    Opening PCAP Meta File: /tmp/yaf_20141223141600_00000.meta
    Opening PCAP File: /data/big.pcap
    Opening output PCAP file /tmp/YMSG.pcap
    Found 41 packets that match criteria


Using getFlowKeyHash and YAF {#getkeyhash}
---------------------------

The second approach is to calculate the flow key hash using **getFlowKeyHash**
and generate a PCAP file with **yaf** for only the flow you are searching for.
This approach works well if you know which PCAP file the flow is contained in.
Assuming we have already run **yaf** and **rwipfix2silk**, we can search for
a particular flow using rwfilter and pipe it to getFlowKeyHash to generate
the hash for the particular flow:

    $ rwfilter --application=5050 --pass-dest=stdout /tmp/yaf2flow.rw \
               | rwsilk2ipfix | getFlowKeyHash
                sIP|            dIP|sPort|dPort|pro| vlan|      hash|                  ms
        10.10.0.208|  98.136.48.106|50997| 5050|  6|  900|2549564224|       1296251585607
      98.136.48.106|    10.10.0.208| 5050|50997|  6|  900|1131976655|       1296251585607
        10.10.0.208|   98.136.48.48|51094| 5050|  6|  900|2538881818|       1296251606219
       98.136.48.48|    10.10.0.208| 5050|51094|  6|  900|1131976502|       1296251606219

Now that we have the flow key hash and start time, we can run **yaf** as
follows:

    $ yaf --in /data/big.pcap --no-output --pcap /tmp/YMSG.pcap \
          --hash 2549564224 --stime 1296251585607 --max-payload=2000

    $ capinfos -c /tmp/YMSG.pcap
    File name:           /tmp/YMSG.pcap
    Number of packets:   41

The ``--max-payload`` option is required for this approach and it should
be set to something larger than the typical MTU to ensure
you get the full packet.  You can think of max-payload as snaplen. If
you set it to something small, all your packets will be truncated to
that length.

Using a BPF Filter {#bpf}
------------------

The third approach is to use a BPF filter.  Sometimes it can be a bit difficult to
format the filter string correctly (especially when there are VLAN tags)
 and it may not weed out all of the data we don't want.  The following BPF filter
should suffice:

    $ yaf --in /data/big.pcap \
          --out /tmp/5050.yaf \
          --pcap /tmp/YMSG_ \
          --filter="port 50997 or (vlan and port 50997) and host 98.136.48.106" \
          --verbose
    [2014-01-27 20:46:44] yaf starting
    [2014-01-27 20:46:44] Reading packets from /data/big.pcap
    [2014-01-27 20:46:46] Processed 44 packets into 4 flows:
    [2014-01-27 20:46:46]   Mean flow rate 2.20/s.
    [2014-01-27 20:46:46]   Mean packet rate 24.21/s.
    [2014-01-27 20:46:46]   Virtual bandwidth 0.0292 Mbps.
    [2014-01-27 20:46:46]   Maximum flow table size 1.
    [2014-01-27 20:46:46]   3 flush events.
    [2014-01-27 20:46:46]   3 asymmetric/unidirectional flows detected
    [2014-01-27 20:46:46] Assembled 0 fragments into 0 packets:
    [2014-01-27 20:46:46]   Expired 0 incomplete fragmented packets.
    [2014-01-27 20:46:46]   Maximum fragment table size 0.
    [2014-01-27 20:46:46] yaf Exported 1 stats records.
    [2014-01-27 20:46:46] yaf terminating

As you can see, we actually captured 4 flows with the above BPF Filter.
You could use **yafscii** to view the flows:

    $ yafscii --in /tmp/5050.yaf --out -
    2011-01-28 21:53:05.607 - 21:53:27.568 (21.961 sec) tcp 10.10.0.208:50997 => 98.136.48.106:5050 452bc00b:65e6c66b S/APRS:AS/APSF vlan 384:384 (23/3250 <-> 18/3264) rtt 78 ms
    2011-01-28 21:53:27.568 tcp 10.10.0.208:50997 => 98.136.48.106:5050 452bc409 R/0 vlan 384 (1/40 ->)
    2011-01-28 21:53:27.688 tcp 10.10.0.208:50997 => 98.136.48.106:5050 452bc409 R/0 vlan 384 (1/40 ->)
    2011-01-28 21:53:27.688 tcp 10.10.0.208:50997 => 98.136.48.106:5050 452bc409 R/0 vlan 384 (1/40 ->)

**capinfos** can be used to confirm how many packets are in the PCAP.

    $ capinfos -c /tmp/YMSG_20140127204003_00000.pcap
    File name:           /tmp/YMSG_20140127204003_00000.pcap
    Number of packets:   44

Using the BPF filter with **yaf** captured 3 extra packets that were not technically
apart of this flow.  However, now that we have a smaller PCAP, we can use
wireshark or a similar tool to view the payload and perform a deeper
analysis of the data.  You could also use the BPF filter and the
``--pcap-per-flow`` option (described in the following paragraphs) to ensure
you only get the packets associated with a flow.

Pcap-per-flow {#pcap-per-flow}
-------------

The fourth (and not recommended) way is to use the ``--pcap-per-flow`` option.
The ``--pcap-per-flow``
option will create at least 1 PCAP file for each flow in the input
PCAP file.  It is not advisable to use this option in most cases, but when
combined with other options, it is useful.

First create a temporary directory to place all the small PCAP files
and then run YAF as follows:

    $ mkdir /tmp/pcap

    $ yaf --in /data/big.pcap \
          --out /tmp/5050.yaf \
          --pcap /tmp/pcap \
          --pcap-per-flow \
          --max-payload=1600 \
          --verbose

The ``--max-payload`` option is required with pcap-per-flow and it should
be set to something larger than the typical MTU to ensure
you get the full packet.  You can think of max-payload as snaplen. If
you set it to something small, all your packets will be truncated to
that length.

In ``/tmp/pcap`` you will see a large amount (depending on how large and diverse
your PCAP file is) of file directories that are 3 digit numbers.
**yaf** uses the last three digits of the start time (in milliseconds)
as the file directory, and the flow key hash, start time, and
serial number as the filename.  Depending on how large the flow
is, **yaf** may have created multiple PCAP files for that flow.
The default size is 25 MB, and can be modified by using the
``--max-pcap`` option.

To quickly determine which PCAP we are interested in, we can
use the **getFlowKeyHash** program again:

    $ getFlowKeyHash --sip4 10.10.0.208 \
      		 --dip4 98.136.48.106 \
    		 --sport 50997 --dport 5050 \
    		 --protocol 6 --vlan 900 \
    		 --date 2011-01-28 --time 21:53:05.607

                sIP|            dIP|sPort|dPort|pro| vlan|      hash|                  ms
        10.10.0.208|  98.136.48.106|50997| 5050|  6|  900|2549564224|       1296251585607

    FILE PATH: 607/2549564224-201112821535_0.pcap

The **getFlowKeyHash** provides the file path to your PCAP:

    $ capinfos -c /tmp/pcap/607/2549564224-20110128215305_0.pcap
    File name:           /tmp/pcap/607/2549564224-20110128215305_0.pcap
    Number of packets:   41

Multiple Input Files {#multiple}
=====================

This tutorial has presented four different ways to slice a
large, single PCAP for a given flow.
This same process can be used over multiple PCAP files as well.  Often
PCAP is captured using tcpdump, rolling files when they reach a particular
size or for a given time period.  **yaf** can read multiple files at a time.
You could run **yaf** on each PCAP file, but flows will be closed each time
**yaf** finishes reading a file.  It is best to use the ``--caplist`` option with
**yaf** so that **yaf** uses the same flow table to process all the PCAPs. When
providing the ``--caplist`` option to **yaf**, the argument to ``--in`` must be an
ordered, newline-delimited list of pathnames to the PCAP files.  Blank
lines and lines beginning with the character '#' are ignored.  The files
must be listed in ascending time order, as **yaf** rejects out-of-order packets.

    $ ls -d -1 -rt /tmp/pcap/** > /tmp/yaf_cap_file.txt
    $ cat /tmp/yaf_cap_file.txt
    /tmp/pcap/pcap1.pcap
    /tmp/pcap/pcap2.pcap
    /tmp/pcap/pcap3.pcap
    /tmp/pcap/pcap4.pcap
    /tmp/pcap/pcap5.pcap
    /tmp/pcap/pcap6.pcap
    /tmp/pcap/pcap7.pcap
    /tmp/pcap/pcap8.pcap
    /tmp/pcap/pcap9.pcap
    /tmp/pcap/pcap10.pcap

    $ yaf --in /tmp/yaf_cap_file.txt \
          --caplist \
          --noerror \
          --out /dev/null \
          --pcap-meta-file /tmp/yaf_meta_pcap.txt -v

Additionally, you may want to use the ``--noerror`` option which will
ensure that **yaf** continues to process the files even if it runs
into an error with one of the PCAP files (sometimes there
can be a truncated packet at the end of a PCAP.)

*Note: the PCAP metadata file will rotate if it reaches the
maximum file size for your operating system.*

The **yafMeta2Pcap** program can take the same caplist file used
as the argument to ``--in`` for **yaf**.

    $ yafMeta2Pcap --caplist /tmp/yaf_cap_file.txt \
                   --pcap-meta-file=/tmp/yaf_meta_pcap.txt \
                   --out /tmp/YMSG.pcap \
                   --hash 2549564224 \
                   --time 1296251585607 -v

*Note: **yafMeta2Pcap** will only open the PCAP files that contain
the flow of interest.*

Next: [How to configure yaf to capture rolling PCAP files.](yaf_pcap2.html)







