/*
** Copyright (C) 2001-2023 by Carnegie Mellon University.
**
** @OPENSOURCE_LICENSE_START@
**
** SiLK 3.22.0
**
** Copyright 2023 Carnegie Mellon University.
**
** NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
** INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
** UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
** AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
** PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
** THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
** ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
** INFRINGEMENT.
**
** Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
** contact permission@sei.cmu.edu for full terms.
**
** [DISTRIBUTION STATEMENT A] This material has been approved for public
** release and unlimited distribution.  Please see Copyright notice for
** non-US Government use and distribution.
**
** GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
**
** Contract No.: FA8702-15-D-0002
** Contractor Name: Carnegie Mellon University
** Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
**
** The Government's rights to use, modify, reproduce, release, perform,
** display, or disclose this software are restricted by paragraph (b)(2) of
** the Rights in Noncommercial Computer Software and Noncommercial Computer
** Software Documentation clause contained in the above identified
** contract. No restrictions apply after the expiration date shown
** above. Any reproduction of the software or portions thereof marked with
** this legend must also reproduce the markings.
**
** Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
** Trademark Office by Carnegie Mellon University.
**
** This Software includes and/or makes use of Third-Party Software each
** subject to its own license.
**
** DM23-0973
**
** @OPENSOURCE_LICENSE_END@
*/

/*
** intervalstats.c:
**
**      support library to calculate statistics from interval-based
**      frequency distributions.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: intervalstats.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>
#include "interval.h"


/* EXTERNAL VARIABLES */

/*
 * intervals are defined for each protocol separately. Till we decide
 * we want to change it, treat icmp like udp
 */
uint32_t tcpByteIntervals[NUM_INTERVALS] = {
    40,60,100,150,256,1000,10000,100000,1000000,0xFFFFFFFF
};
uint32_t udpByteIntervals[NUM_INTERVALS] = {
    20,40,80,130,256,1000,10000,100000,1000000,0xFFFFFFFF
};
uint32_t tcpPktIntervals[NUM_INTERVALS] = {
    3,4,10,20,50,100,500,1000,10000,0xFFFFFFFF
};
uint32_t udpPktIntervals[NUM_INTERVALS] = {
    3,4,10,20,50,100,500,1000,10000,0xFFFFFFFF
};
uint32_t tcpBppIntervals[NUM_INTERVALS] = {
    40,44,60,100,200,400,600,800,1500,0xFFFFFFFF
};
uint32_t udpBppIntervals[NUM_INTERVALS] = {
    20,24,40,100,200,400,600,800,1500,0xFFFFFFFF
};


/* LOCAL VARIABLES */

static uint32_t* cumFrequencies = NULL;
static double retArray[3];      /* return results via this buffer */
static uint64_t total;
static uint32_t quartileIndices[3];
static uint32_t quartileValues[3];

/* FUNCTION DECLARATIONS */

static double
getQuantile(
    const uint32_t     *data,
    const uint32_t     *boundaries,
    uint32_t            numIntervals,
    uint32_t            quantile);
static void
intervalSetup(
    const uint32_t     *data,
    uint32_t            numIntervals);
static void intervalTeardown(void);


/* FUNCTION DEFINITIONS */

static void
intervalTeardown(
    void)
{
    if (cumFrequencies != NULL) {
        free(cumFrequencies);
        cumFrequencies = NULL;
    }
}

/* pure noops */
int
intervalInit(
    void)
{
    return 0;
}

void
intervalShutdown(
    void)
{
    return;
}


/*
 * intervalSetup:
 *      Compute cum freq into cumFrequencies vector.
 *      Mark 25, 50, 75th percentile interval indices.
 *      Record cumulative total in global total.
 * Input:
 *      data vector
 * Output: None
 * Side Effects: globals cumFrequencies, quartileIndices, total set.
 */
static void
intervalSetup(
    const uint32_t     *data,
    uint32_t            numIntervals)
{
    register uint32_t i;

    if (cumFrequencies != NULL) {
        free(cumFrequencies);
    }

    cumFrequencies = (uint32_t *)malloc(numIntervals * sizeof(uint32_t));
    if (NULL == cumFrequencies) {
        skAppPrintOutOfMemory("array");
        exit(EXIT_FAILURE);
    }
    cumFrequencies[0] = data[0];
    for (i = 1; i < numIntervals; i++) {
        cumFrequencies[i] = cumFrequencies[i-1] + data[i];
    }
    total = cumFrequencies[numIntervals - 1];
    quartileValues[0] = total >> 2;             /* 1/4th */
    quartileValues[1] = total >> 1;
    quartileValues[2] = 3 * quartileValues[0];

    /* record quantile indices */
    for (i = 0; i < numIntervals; i++) {
        if (quartileValues[0] <= cumFrequencies[i]) {
            quartileIndices[0] = i;
            break;
        }
    }
    for (i = 0; i < numIntervals; i++) {
        if (quartileValues[1] <= cumFrequencies[i]) {
            quartileIndices[1] = i;
            break;
        }
    }
    for (i = 0; i < numIntervals; i++) {
        if (quartileValues[2] <= cumFrequencies[i]){
            quartileIndices[2] = i;
            break;
        }
    }
    return;
}

#define MC 0
#if     MC
/*
** getQuantile:
**      return the indicated quantile expressed as a number between 1-100
** Input: the desired quantile.
** Output: the quantile
** Side Effects: None
*/
static double
getQuantile(
    const uint32_t     *data,
    const uint32_t     *boundaries,
    uint32_t            numIntervals,
    uint32_t            quantile)
{
    int32_t intervalIndex;
    int32_t intervalOffset;
    double intervalSlope, result;

    /*
     * First, find the interval
     */
    if (quantile == 25) {
        intervalIndex = quartileIndices[0];
    } else if (quantile == 50) {
        intervalIndex = quartileIndices[1];
    } else if (quantile == 75) {
        intervalIndex = quartileIndices[2];
    } else {
        /* dont have it. Calculate the desired index */
        int i;
        uint32_t quantileValue = quantile * total;
        for (i = 0; i < numIntervals; i++) {
            if (quantileValue <= cumFrequencies[i]) {
                intervalIndex = i;
                break;
            }
        }
        if (i == numIntervals) {
            intervalIndex = numIntervals - 1;
        }
    }
    if (intervalIndex == 0) {
        /*
         * Calculate based on flat percentage difference
         */
        intervalSlope = (intervalIndex * 1.0)/(data[intervalIndex] * 1.0);
        return intervalSlope * data[intervalIndex];
    }

    if (intervalIndex == (numIntervals - 1) ) {
        /* in last interval which has a high value of 0xFFFFFFFF */
        return 0.00;
    }
    intervalOffset = cumFrequencies[intervalIndex]
        - cumFrequencies[intervalIndex -1];
    intervalSlope = (intervalOffset * 1.0) /
        (1.0 * data[intervalIndex]);
    result = (intervalSlope * (boundaries[intervalIndex]
                               - boundaries[intervalIndex - 1]))
        + (1.0 * boundaries[intervalIndex -1]);
    return result;
}
#else
static double
getQuantile(
    const uint32_t  UNUSED(*data),
    const uint32_t         *boundaries,
    uint32_t                numIntervals,
    uint32_t                quantile)
{
    /*
    ** Blo = boundary value at the lower index of the cumFreq containing
    **          the quantile value
    ** Bhi = boundary value at the higher index of the cumFreq containing
    **          the quantile value
    **
    ** Vq = cum freq at the quantile desired ( = quantile frac * total )
    **
    ** Vhi = cumfreq value >= Vq
    ** Vlo = cumfreq value 1 lower than Vhi
    */
    register uint32_t Blo, Bhi, Vlo, Vhi, Vq;
    register uint32_t intervalIndex = 0;
    register uint32_t i;

    /*
     * First, find the interval
     */
    if (quantile == 25) {
        intervalIndex = quartileIndices[0];
        Vq = quartileValues[0];
    } else if (quantile == 50) {
        intervalIndex = quartileIndices[1];
        Vq = quartileValues[1];
    } else if (quantile == 75) {
        intervalIndex = quartileIndices[2];
        Vq = quartileValues[2];
    } else {
        /* dont have it. Calculate the desired index */
        Vq = quantile * total;
        for (i = 0; i < numIntervals; i++) {
            if (Vq <= cumFrequencies[i]) {
                intervalIndex = i;
                break;
            }
        }
    }

    Bhi = boundaries[intervalIndex];
    Vhi = cumFrequencies[intervalIndex];
    if (intervalIndex == 0) {
        Blo = 0;
        Vlo = 0;
    } else {
        Blo = boundaries[intervalIndex - 1 ];
        Vlo = cumFrequencies[intervalIndex - 1 ];
    }
    return Blo + ( (double) (Vq -Vlo) / (double) (Vhi - Vlo) )
        * (double)(Bhi - Blo);
}
#endif


double *
intervalQuartiles(
    const uint32_t     *data,
    const uint32_t     *boundaries,
    uint32_t            numIntervals)
{
    intervalSetup(data, numIntervals);
    retArray[0] = getQuantile(data, boundaries, numIntervals, 25);
    retArray[1] = getQuantile(data, boundaries, numIntervals, 50);
    retArray[2] = getQuantile(data, boundaries, numIntervals, 75);
    intervalTeardown();
    return retArray;
}


/*
** intervalMoments:
**      calculate the mean and variance for interval freq data.
** Inputs: uint32_t vector of data, boundaries;
**         uint32_t # of elements in the vectors.
** Outputs: double *array of mean and var.
** Side Effects: None.
*/
double *
intervalMoments(
    const uint32_t         *data,
    const uint32_t  UNUSED(*boundaries),
    uint32_t                numIntervals)
{
    intervalSetup(data, numIntervals);

    intervalTeardown();
    return retArray;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
