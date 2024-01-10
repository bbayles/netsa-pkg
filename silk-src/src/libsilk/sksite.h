/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
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
**  sksite.h
**
**    An interface to site-specific settings.
**
*/
#ifndef _SKSITE_H
#define _SKSITE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKSITE_H, "$SiLK: sksite.h c05ad63a27aa 2023-05-12 19:43:56Z mthomas $");

#include <silk/silk_types.h>

/**
 *  @file
 *
 *    The interface to site-specific settings, many of which are
 *    determined by the silk.conf file.
 *
 *    This file is part of libsilk.
 */


/**
 *    Name of environment variable that specfies the root directory of
 *    the repository of hourly SiLK Flow files.
 */
#define SILK_DATA_ROOTDIR_ENVAR "SILK_DATA_ROOTDIR"

/**
 *    Name of environment variable that specfies the full path to the
 *    silk.conf configuration file.
 */
#define SILK_CONFIG_FILE_ENVAR "SILK_CONFIG_FILE"


/* Add an option for processing the silk.conf configuration file */
#define SK_SITE_FLAG_CONFIG_FILE  0x01


/** Configuration and Initialization **********************************/

/**
 *    Initialize everything related to the site *except* the sensor
 *    configuration from the config file.  The parameter 'levels' is
 *    currently unused.
 *
 *    Application writers do not need to call this function as it is
 *    called by skAppRegister().
 */
int
sksiteInitialize(
    int                 levels);

/**
 *    Register options according to the value of 'flags'.
 *
 *    The parameter 'flags' is the bitsize-OR of the SK_SITE_FLAG_*
 *    values listed above.
 */
int
sksiteOptionsRegister(
    uint32_t            flags);

/**
 *    Print usage information for any options that were registered by
 *    sksiteOptionsRegister() to the file handle 'fh'.
 */
void
sksiteOptionsUsage(
    FILE               *fh);

/**
 *    Read the SiLK site configuration file (silk.conf) from the path
 *    set by sksiteSetConfigPath() or from one of the default
 *    locations:
 *
 *      -- location specified by SILK_CONFIG_FILE environment variable
 *      -- SILK_DATA_ROOTDIR/silk.conf
 *      -- SILK_PATH/share/silk/silk.conf, SILK_PATH/share/silk.conf
 *      -- bindir/../share/silk/silk.conf, bindir/../share/silk.conf
 *
 *    where bindir is location of current application.
 *
 *    Return 0 if the configuration has properly loaded; or non-zero
 *    otherwise.  Return -1 to indicate errors parsing the file, or -2
 *    if the site configuration file cannot be found.
 *
 *    If the function returns -2 to indicate the file was not found,
 *    you may called it again, presumably after calling
 *    sksiteSetConfigPath() or sksiteSetRootDir().
 *
 *    Once the function returns 0 or -1, nothing will happen on
 *    subsequent call to the function.
 *
 *    If verbose is 1, this function will report failures to open the
 *    file as errors.  If verbose is 0, only parsing failures will be
 *    reported.  (For example, if you intend to try opening several
 *    files in a row to find the correct file, verbose should be 0 to
 *    avoid several reports of open failures.)
 *
 *    NOTE: This function should be called single-threaded.
 */
int
sksiteConfigure(
    int                 verbose);

/**
 *    Set the path to the SiLK site configuration file.  Return 0
 *    unless 'filename' is too long or if the caller is attempting to
 *    invoke the function after the config file has been read.
 */
int
sksiteSetConfigPath(
    const char         *filename);

/**
 *    Fill 'buffer' with the path to the site configuration file.
 *    'buffer' is a character array whose length is 'bufsize'.
 *    Returns a pointer to 'buffer', or NULL if 'buffer' is too small
 *    to hold the path.
 *
 *    If the application has been configured, this function returns
 *    the path that sksiteConfigure() used.  Otherwise, the function
 *    returns the path that would be used by sksiteConfigure().
 */
char *
sksiteGetConfigPath(
    char               *buffer,
    size_t              bufsize);

/**
 *    Destroy all the data structures and deallocate all memory
 *    associated with the site.
 *
 *    Application writers do not need to call this function as it is
 *    called by skAppUnregister().
 */
void
sksiteTeardown(
    void);

/** Iterators *********************************************************/

/**
 *    sk_sensor_iter_t is an iterator to visit sensors.
 *
 *    The iterator should be created on the stack.  Its definition is
 *    given at the end of this file.
 *
 *    sksiteSensorIterator() creates an iterator over all sensors.
 *
 *    sksiteClassSensorIterator() creates an iterator over all
 *    sensors in a class.
 *
 *    sksiteSensorgroupSensorIterator() creates an iterator over all
 *    sensors in a sensorgroup.
 */
typedef struct sk_sensor_iter_st        sk_sensor_iter_t;

/**
 *    sk_class_iter_t is an iterator to visit classes
 *
 *    The iterator should be created on the stack.  Its definition is
 *    given at the end of this file.
 *
 *    sksiteClassIterator() creates an iterator over all classes.
 *
 *    sksiteSensorClassIterator() creates an iterator over all
 *    classes that a sensor belongs to.
 */
typedef struct sk_class_iter_st         sk_class_iter_t;

/**
 *    sk_sensorgroup_iter_t is an iterator to visit sensor groups.
 *
 *    The iterator should be created on the stack.  Its definition is
 *    given at the end of this file.
 *
 *    sksiteSensorgroupIterator() creates an iterator over all
 *    sensor groups.
 *
 *    sksiteSensorSensorgroupIterator() creates an iterator over all the
 *    sensor groups that a sensor is a member of.
 */
typedef struct sk_sensorgroup_iter_st   sk_sensorgroup_iter_t;

/**
 *    sk_flowtype_iter_t is an iterator to visit flowtypes.
 *
 *    The iterator should be created on the stack.  Its definition is
 *    given at the end of this file.
 *
 *    sksiteFlowtypeIterator() creates an iterator over all flowtypes.
 *
 *    sksiteClassFlowtypeIterator() creates an iterator over all
 *    flowtypes in a class.
 *
 *    sksiteClassDefaultFlowtypeIterator() creates an iterator over
 *    the default flowtypes in a class.
 */
typedef struct sk_flowtype_iter_st      sk_flowtype_iter_t;

typedef sk_class_iter_t         class_iter_t        SK_GCC_DEPRECATED;
typedef sk_flowtype_iter_t      flowtype_iter_t     SK_GCC_DEPRECATED;
typedef sk_sensor_iter_t        sensor_iter_t       SK_GCC_DEPRECATED;
typedef sk_sensorgroup_iter_t   sensorgroup_iter_t  SK_GCC_DEPRECATED;


/*
 *  more_data = sksite<THING>InteratorNext(iter, &out_<THING>_id);
 *
 *    These take a pointer to an iterator and a pointer to the type
 *    being iterated over.  If the iterator is empty, 0 is returned.
 *    Otherwise, out_<THING>_id is set to the next valid ID and 1 is
 *    returned.
 */

/**
 *  more_data = sksiteSensorInteratorNext(iter, &out_sensor_id);
 *
 *    Fill 'out_sensor_id' with the next sensor ID and return 1, or
 *    return 0 if no more sensors exist on the iterator.
 */
int
sksiteSensorIteratorNext(
    sk_sensor_iter_t   *iter,
    sk_sensor_id_t     *out_sensor_id);

/**
 *  more_data = sksiteClassInteratorNext(iter, &out_class_id);
 *
 *    Fill 'out_class_id' with the next class ID and return 1, or
 *    return 0 if no more classs exist on the iterator.
 */
int
sksiteClassIteratorNext(
    sk_class_iter_t    *iter,
    sk_class_id_t      *out_class_id);

/**
 *  more_data = sksiteSensorgroupInteratorNext(iter, &out_sensorgroup_id);
 *
 *    Fill 'out_sensorgroup_id' with the next sensorgroup ID and return 1, or
 *    return 0 if no more sensorgroups exist on the iterator.
 */
int
sksiteSensorgroupIteratorNext(
    sk_sensorgroup_iter_t  *iter,
    sk_sensorgroup_id_t    *out_sensorgroup_id);

/**
 *  more_data = sksiteFlowtypeInteratorNext(iter, &out_flowtype_id);
 *
 *    Fill 'out_flowtype_id' with the next flowtype ID and return 1, or
 *    return 0 if no more flowtypes exist on the iterator.
 */
int
sksiteFlowtypeIteratorNext(
    sk_flowtype_iter_t *iter,
    sk_flowtype_id_t   *out_flowtype_id);


/** Sensors ***********************************************************/

/**
 *    Create the sensor 'sensor_name' with id 'sensor_id'.  It is an
 *    error to create a sensor with an ID that is already allocated.
 *
 *    Return 0 on success.  Return -1 if an error occurs; error
 *    conditions include sensor ID already in use, sensor name already
 *    in use, illegal sensor name, out of memory.
 *
 *    To check whether a string is legal as a sensor name, use
 *    sksiteSensorNameIsLegal().
 *
 *    Use sksiteSensorLookup() to get a sensor ID given the name, and
 *    use sksiteSensorGetName() to get a sensor name given the ID.
 *
 *    Use sksiteSensorIterator() to view all created sensors.
 */
int
sksiteSensorCreate(
    sk_sensor_id_t      sensor_id,
    const char         *sensor_name);

/**
 *    Find the sensor ID for a sensor given its name.  Return
 *    SK_INVALID_SENSOR if no sensor is found with the given name.
 *
 *    Use sksiteSensorGetName() to get a sensor's name given its ID.
 *
 *    Use sksiteSensorExists() to check whether a sensor ID is known.
 */
sk_sensor_id_t
sksiteSensorLookup(
    const char         *sensor_name);

/**
 *    Return 1 if a sensor with the given sensor ID exists, 0 if no
 *    such sensor has been defined.
 *
 *    Use sksiteSensorIterator() to visit all known sensor IDs.
 */
int
sksiteSensorExists(
    sk_sensor_id_t      sensor_id);

/**
 *    Return the minimum sensor ID that has been allocated to a
 *    sensor.  Return (sk_sensor_id_t)(-1) if no sensors yet exist.
 */
sk_sensor_id_t
sksiteSensorGetMinID(
    void);

/**
 *    Return the maximum sensor ID that has been allocated to a
 *    sensor.  Return (sk_sensor_id_t)(-1) if no sensors yet exist.
 *
 *    The caller may add one to this value to get the lowest ID that
 *    is guaranteed not to have been allocated.
 *
 *    There is no guarantee that every sensor ID between
 *    sksiteSensorGetMinID() and sksiteSensorGetMaxID() is in use.
 */
sk_sensor_id_t
sksiteSensorGetMaxID(
    void);

/**
 *    Return the length of the longest currently known sensor name,
 *    or a minimum value.  This result is suitable for choosing the
 *    size of a display column for sensor names and/or IDs.
 *
 *    The return value does not include the trailing '\0'.  See also
 *    SK_MAX_STRLEN_SENSOR in silk_types.h.
 */
size_t
sksiteSensorGetMaxNameStrLen(
    void);

/**
 *    Copy the name of the sensor with the given sensor ID into the
 *    given buffer of size buffer_size.  If the name is longer than
 *    buffer_size, the value returned is truncated with a '\0' in the
 *    final position.
 *
 *    Return the number of characters that would have been written if
 *    the buffer had been long enough.  This length does not include
 *    the trailing '\0'.
 *
 *    A buffer one character longer than SK_MAX_STRLEN_SENSOR is
 *    capable of holding all valid sensor names.
 *
 *    If 'sensor_id' is SK_INVALID_SENSOR, the string "?" is copied
 *    into 'buffer'.  If 'sensor_id' is not known to the configuration
 *    file (that is, it does not have a name), put the numeric ID into
 *    'buffer'.  Use sksiteSensorExists() to determine if a sensor ID
 *    is known.
 *
 *    Use sksiteSensorLookup() to get a sensor ID given a sensor name.
 */
int
sksiteSensorGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_sensor_id_t      sensor_id);

/**
 *    Return 1 if the sensor with ID sensor_id is defined to be in
 *    the class with ID class_id.  Return 0 otherwise.
 *
 *    Use sksiteClassAddSensor() to add a sensor to a class.  Use
 *    sksiteClassAddSensorgroup() to add multiple sensors to a class.
 */
int
sksiteIsSensorInClass(
    sk_sensor_id_t      sensor_id,
    sk_class_id_t       class_id);

/**
 *    Return 1 if the sensor with ID sensor_id is defined to be in
 *    the sensor-group with ID sensorgroup_id.  Return 0 otherwise.
 *
 *    Use sksiteSensorgroupAddSensor() to add a sensor to a sensor group.  Use
 *    sksiteSensorgroupAddSensorgroup() to add multiple sensors to a sensor
 *    group.
 *
 *    Since SiLK 3.21.0.
 */
int
sksiteIsSensorInSensorgroup(
    sk_sensor_id_t      sensor_id,
    sk_sensorgroup_id_t sensorgroup_id);

/**
 *    Set iter to be an iterator that loops over all defined sensors.
 *    Use sksiteSensorIteratorNext() to visit each sensor ID.
 */
void
sksiteSensorIterator(
    sk_sensor_iter_t   *iter);

/**
 *    Set iter to be an iterator that loops over all of the classes
 *    that possess the given sensor.  Use sksiteClassIteratorNext() to
 *    visit each class ID.  The iterator is valid even when
 *    'sensor_id' is not a known sensor ID.
 *
 *    Use sksiteSensorGetClassCount() to get the number of classes
 *    that a sensor belongs to.
 *
 *    Use sksiteIsSensorInClass() to determine whether a sensor is in
 *    a specific class.
 */
void
sksiteSensorClassIterator(
    sk_sensor_id_t      sensor_id,
    sk_class_iter_t    *iter);

/**
 *    Set iter to be an iterator that loops over all of the sensor groups that
 *    the given sensor is a member of.  Use sksiteSensorgroupIteratorNext() to
 *    visit each sensor-group ID.  The iterator is valid even when 'sensor_id'
 *    is not a known sensor ID.
 *
 *    Use sksiteIsSensorInSensorgroup() to determine whether a sensor is in a
 *    specific sensor-group.
 *
 *    Since SiLK 3.21.0.
 */
void
sksiteSensorSensorgroupIterator(
    sk_sensor_id_t          sensor_id,
    sk_sensorgroup_iter_t  *iter);

/**
 *    Check whether 'name' is a valid sensor name.
 *
 *    Return 0 if the given string is a legal sensor name containing
 *    no illegal characters and having a length (as returned by
 *    strlen()) between 1 and SK_MAX_STRLEN_SENSOR inclusive.
 *
 *    Return -1 if the name does not begin with an alpha character, -2
 *    if the name is too short, -3 if it is too long.  A positive
 *    return value indicates that the character at that position is
 *    invalid.
 */
int
sksiteSensorNameIsLegal(
    const char         *name);

/**
 *    Return the number of classes that the given sensor belongs to.
 *    Return 0 if 'sensor_id' is not a known sensor ID.
 *
 *    Use sksiteSensorClassIterator() to iterate over those classes.
 */
int
sksiteSensorGetClassCount(
    sk_sensor_id_t      sensor_id);

/**
 *    Return the description of the sensor.
 *
 *    A sensor's description is specified in the silk.conf file and
 *    are solely for use by the end-user; the description can be
 *    printed with rwsiteinfo.  Return NULL if no sensor has the ID
 *    'sensor_id' or if the description has not been set.
 */
const char *
sksiteSensorGetDescription(
    sk_sensor_id_t      sensor_id);

/**
 *    Set the description of the given sensor, removing any previous
 *    description.  Return 0 on success.  Return -1 if 'sensor_id' is
 *    not a valid sensor or on memory allocation errror.  Specify
 *    'sensor_description' as NULL to clear the current description.
 */
int
sksiteSensorSetDescription(
    sk_sensor_id_t      sensor_id,
    const char         *sensor_description);

/** Classes ***********************************************************/

/**
 *    Create the class 'class_name' with id 'class_id'.  It is an
 *    error to create a class with an ID that is already allocated.
 *
 *    Return 0 on success.  Return -1 if an error occurs; error
 *    conditions include class ID already in use, class name already
 *    in use, class name is illegal, out of memory.
 *
 *    Use sksiteClassLookup() to get a class ID given the name, and
 *    use sksiteClassGetName() to get a class name given the ID.
 *
 *    Use sksiteClassIterator() to view all created classes.
 */
int
sksiteClassCreate(
    sk_class_id_t       class_id,
    const char         *class_name);

/**
 *    Set the default class for fglobbing.  Return 0 on success, or -1
 *    if 'class_id' is not a valid class.  Use sksiteClassGetDefault()
 *    to get the default class.
 */
int
sksiteClassSetDefault(
    sk_class_id_t       class_id);

/**
 *    Return the default class for fglobbing.  Use
 *    sksiteClassSetDefault() to set the default class.
 */
sk_class_id_t
sksiteClassGetDefault(
    void);

/**
 *    Find the class ID for a class given its name.  Return
 *    SK_INVALID_CLASS if no class is found with the given name.
 *
 *    Use sksiteClassGetName() to get a class's name given its ID.
 *
 *    Use sksiteClassExists() to check whether a class ID is known.
 */
sk_class_id_t
sksiteClassLookup(
    const char         *class_name);

/**
 *    Return 1 if a class with the given class ID exists, 0 if no
 *    such class has been defined.
 *
 *    Use sksiteClassIterator() to visit all known class IDs.
 */
int
sksiteClassExists(
    sk_class_id_t       class_id);

/**
 *    Return the maximum class ID that has been allocated to a class.
 *    Return (sk_class_id_t)(-1) if no classes yet exist.
 *
 *    The caller may add one to this value to get the lowest ID that
 *    is certain not to have been allocated.
 *
 *    Note that not all IDs up to the maximum may have been allocated.
 */
sk_class_id_t
sksiteClassGetMaxID(
    void);

/**
 *    Return the length of the longest currently known class name, or
 *    a minimum value.  This result is suitable for choosing the size
 *    of a display column for class names and/or IDs.
 *
 *    The return value does not include the trailing '\0'.  See also
 *    SK_MAX_STRLEN_FLOWTYPE in silk_types.h.
 */
size_t
sksiteClassGetMaxNameStrLen(
    void);

/**
 *    Copy the name of the class with the given class ID into the
 *    given buffer of size buffer_size.  If the name is longer than
 *    buffer_size, the value returned is truncated with a '\0' in the
 *    final position.
 *
 *    A buffer one character longer than SK_MAX_STRLEN_FLOWTYPE is
 *    capable of holding all valid class names.
 *
 *    Return the number of characters that would have been written if
 *    the buffer had been long enough.  This length does not include
 *    the trailing '\0'.
 *
 *    If 'class_id' is SK_INVALID_CLASS, the string "?" is copied into
 *    'buffer'.  If 'class_id' is not known to the configuration file
 *    (that is, it does not have a name), put the numeric ID into
 *    'buffer'.  Use sksiteClassExists() to determine if a class ID is
 *    known.
 *
 *    Use sksiteClassLookup() to get a class ID given a class name.
 */
int
sksiteClassGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_class_id_t       class_id);

/**
 *    Add the given sensor to the given class.  A sensor may belong to
 *    multiple classes.  Both the sensor list of 'class_id' and the
 *    class list of 'sensor_id' are updated.
 *
 *    Return 0 on success or if 'sensor_id' already exists on
 *    'class_id'.  Return -1 if 'class_id' is not a known class, if
 *    'sensor_id' is not a known sensor, or on memory allocation
 *    error.
 *
 *    Use sksiteClassCreate() to create a class and
 *    sksiteSensorCreate() to create a sensor.
 *
 *    Call sksiteSensorClassIterator() to visit the classes that use a
 *    sensor; call sksiteClassSensorIterator() to visit the sensors
 *    that a class uses.
 *
 *    See also sksiteClassAddSensorgroup().
 */
int
sksiteClassAddSensor(
    sk_class_id_t       class_id,
    sk_sensor_id_t      sensor_id);

/**
 *    Add every sensor in the given sensorgroup to the given class.
 *
 *    Adding a sensorgroup to a class adds the group's sensors to the class;
 *    no record is kept that the sensorgroup has been added to the class.
 *
 *    Return 0 on success.  Return -1 if 'class_id' is not a known
 *    class, if 'sensorgroup_id' is not a known sensorgroup, or on
 *    memory allocation error.
 *
 *    See also sksiteClassAddSensor().
 */
int
sksiteClassAddSensorgroup(
    sk_class_id_t       class_id,
    sk_sensorgroup_id_t sensorgroup_id);

/**
 *    Set iter to be an iterator that loops over all defined classes.
 *    Use sksiteClassIteratorNext() to visit each class ID.
 */
void
sksiteClassIterator(
    sk_class_iter_t    *iter);

/**
 *    Set iter to be an iterator that loops over all sensors in the
 *    given class.  Use sksiteSensorIteratorNext() to visit each
 *    sensor ID.  The iterator is valid even when 'class_id' is not a
 *    valid class ID.
 *
 *    Use sksiteClassGetSensorCount() to get the number of sensors in
 *    a class.
 *
 *    Use sksiteSensorClassIterator() to iterate over all classes that
 *    a sensor belongs to.
 *
 *    Call sksiteIsSensorInClass() to determine whether a class uses a
 *    specific sensor.
 *
 *    Use sksiteClassAddSensor() and sksiteClassAddSensorgroup() to
 *    add sensors to a class.
 */
void
sksiteClassSensorIterator(
    sk_class_id_t       class_id,
    sk_sensor_iter_t   *iter);

/**
 *    Return the number of sensors in the given class.  Return 0 if
 *    class_id is not known.
 *
 *    Use sksiteClassSensorIterator() to iterate over those sensors.
 */
int
sksiteClassGetSensorCount(
    sk_class_id_t       class_id);

/**
 *    Set iter to be an iterator that loops over all flowtypes in the
 *    given class.  Use sksiteFlowtypeIteratorNext() to visit each
 *    flowtype ID.  The iterator is valid even when 'class_id' is not
 *    a valid class ID.
 *
 *    A flowtype is put into a class when the flowtype is created via
 *    sksiteFlowtypeCreate().
 *
 *    Use sksiteClassDefaultFlowtypeIterator() to visit only the
 *    default flowtypes for a class.
 */
void
sksiteClassFlowtypeIterator(
    sk_class_id_t       class_id,
    sk_flowtype_iter_t *iter);

/**
 *    Set iter to be an iterator that loops over all default flowtypes
 *    for the given class.  The default flowtypes are used when
 *    fglobbing.  Use sksiteSensorIteratorNext() to visit each sensor
 *    ID.  The iterator is valid even when 'class_id' is not a valid
 *    class ID.
 *
 *    Use sksiteClassFlowtypeIterator() to visit all the flowtypes for
 *    a class.
 *
 *    Use sksiteClassAddDefaultFlowtype() to mark a flowtype as being
 *    a default flowtype within a class.
 */
void
sksiteClassDefaultFlowtypeIterator(
    sk_class_id_t       class_id,
    sk_flowtype_iter_t *iter);

/**
 *    Add the given flowtype to the list of default flowtypes for the
 *    given class.  The default flowtypes are used when
 *    fglobbing.
 *
 *    Return 0 on success or if the flowtype is already marked as
 *    being a default type for the class.  Return -1 if 'class_id' is
 *    not a known class, if 'flowtype_id' is not a known flowtype, if
 *    the class of flowtype is not 'class_id', or on memory allocation
 *    error.
 *
 *    Use sksiteClassCreate() to create a class and
 *    sksiteFlowtypeCreate() to create a flowtype.
 *
 *    Use sksiteClassDefaultFlowtypeIterator() to visit the default
 *    flowtypes for a class.
 */
int
sksiteClassAddDefaultFlowtype(
    sk_class_id_t       class_id,
    sk_flowtype_id_t    flowtype_id);

/** Sensorgroups ******************************************************/

/**
 *    Create the group 'sensorgroup_name' with id 'sensorgroup_id'.
 *    It is an error to create a group with an ID that is already
 *    allocated.
 *
 *    Return 0 on success.  Return -1 if an error occurs; error
 *    conditions include sensorgroup ID already in use, sensorgroup
 *    name already in use, out of memory.
 *
 *    Use sksiteSensorgroupLookup() to get a sensorgroup ID given the
 *    name, and use sksiteSensorgroupGetName() to get a sensorgroup
 *    name given the ID.
 */
int
sksiteSensorgroupCreate(
    sk_sensorgroup_id_t sensorgroup_id,
    const char         *sensorgroup_name);

/**
 *    Find the sensorgroup ID for a group given its name.  Returns
 *    SK_INVALID_SENSORGROUP if no group is found with the given name.
 *
 *    Use sksiteSensorgroupGetName() to get a group's name given its ID.
 *
 *    Use sksiteSensorgroupExists() to check whether a group ID is
 *    known.
 */
sk_sensorgroup_id_t
sksiteSensorgroupLookup(
    const char         *sensorgroup_name);

/**
 *    Return 1 if a sensorgroup with the given ID exists, 0 if no such
 *    group has been defined.
 *
 *    Use sksiteSensorgroupIterator() to visit all known group IDs.
 */
int
sksiteSensorgroupExists(
    sk_sensorgroup_id_t sensorgroup_id);

/**
 *    Return the maximum ID that has been allocated to a sensorgroup.
 *    Return (sk_sensorgroup_id_t)(-1) if no groups yet exist.
 *
 *    The caller may add one to this value to get the lowest ID that
 *    is certain not to have been allocated.
 *
 *    Note that not all IDs up to the maximum may have been allocated.
 */
sk_sensorgroup_id_t
sksiteSensorgroupGetMaxID(
    void);

/**
 *    Return the length of the longest currently known group name, or
 *    a minimum value.  This result is suitable for choosing the size
 *    of a display column for group names and/or IDs.
 */
size_t
sksiteSensorgroupGetMaxNameStrLen(
    void);

/**
 *    Copy the name of the group with the given ID into the given
 *    buffer of size buffer_size.  If the name is longer than
 *    buffer_size, the value returned is truncated with a '\0' in the
 *    final position.
 *
 *    Return the number of characters that would have been written if
 *    the buffer had been long enough.  This length does not include
 *    the trailing '\0'.
 *
 *    If 'sensorgroup_id' is SK_INVALID_SENSORGROUP, the string "?" is
 *    copied into 'buffer'.  If 'sensorgroup_id' is not known to the
 *    configuration file (that is, it does not have a name), put the
 *    numeric ID into 'buffer'.  Use sksiteSensorgroupExists() to
 *    determine if a sensorgroup ID is known.
 *
 *    Use sksiteSensorgroupLookup() to get a sensorgroup ID given a
 *    sensorgroup name.
 */
int
sksiteSensorgroupGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_sensorgroup_id_t sensorgroup_id);

/**
 *    Add the given sensor to the given sensorgroup.  A sensor may
 *    belong to multiple sensorgroups.
 *
 *    Return 0 on success or if 'sensor_id' already exists on
 *    'sensorgroup_id'.  Return -1 if 'sensorgroup_id' is not a known
 *    sensorgroup, if 'sensor_id' is not a known sensor, or on memory
 *    allocation error.
 *
 *    Use sksiteSensorgroupCreate() to create a sensorgroup and
 *    sksiteSensorCreate() to create a sensor.
 *
 *    Use sksiteSensorgroupSensorIterator() to visit the sensors are members of
 *    a sensorgroup.
 *
 *    Use sksiteSensorSensorgroupIterator() to visit the sensorgroups that a
 *    sensor is a member of.
 *
 *    See also sksiteSensorgroupAddSensorgroup().
 */
int
sksiteSensorgroupAddSensor(
    sk_sensorgroup_id_t sensorgroup_id,
    sk_sensor_id_t      sensor_id);

/**
 *    Add every sensor in the sensorgroup 'src_sensorgroup' to the sensorgroup
 *    'dest_sensorgroup'.
 *
 *    Adding 'src_sensorgroup' to 'dest_sensorgroup' adds src_sensorgroup's
 *    sensors to dest_sensorgroup; no record is kept that src_sensorgroup has
 *    been added to dest_sensorgroup.  When this call completes, calling
 *    sksiteSensorSensorgroupIterator() on a sensor in src_sensorgroup gives
 *    an iterator that returns both src_sensorgroup and dest_sensorgroup.
 *
 *    Return 0 on success.  Return -1 if 'src_sensorgroup' is not a
 *    known sensorgroup, if 'dest_sensorgroup' is not a known
 *    sensorgroup, or on memory allocation error.
 *
 *    See also sksiteSensorgroupAddSensor().
 */
int
sksiteSensorgroupAddSensorgroup(
    sk_sensorgroup_id_t dest_sensorgroup,
    sk_sensorgroup_id_t src_sensorgroup);

/**
 *    Set iter to be an iterator that loops over all defined
 *    sensorgroups.  Use sksiteSensorgroupIteratorNext() to visit each
 *    sensorgroup ID.
 */
void
sksiteSensorgroupIterator(
    sk_sensorgroup_iter_t  *iter);

/**
 *    Set iter to be an iterator that loops over all sensors in the
 *    given sensorgroup.  Use sksiteSensorIteratorNext() to visit each
 *    sensor ID.  The iterator is valid even when 'sensorgroup_id' is
 *    not a valid sensorgroup ID.
 *
 *    Use sksiteSensorgroupAddSensor() and
 *    sksiteSensorgroupAddSensorgroup() to add sensors to a
 *    sensorgroup.
 */
void
sksiteSensorgroupSensorIterator(
    sk_sensorgroup_id_t     sensorgroup_id,
    sk_sensor_iter_t       *iter);

/** Flowtypes *********************************************************/

/**
 *    Flowtypes represent individual class/type pairs.  Flowtype IDs
 *    are actually recorded in files, while class IDs and types are
 *    not.
 */

/**
 *    Create the flowtype 'flowtype_name' with id 'flowtype_id'.
 *    Associate it with the given class ID and type name.  It is an
 *    error to create a flowtype with an ID that is already allocated.
 *
 *    Return 0 on success.  Return -1 if an error occurs; error
 *    conditions include flowtype ID already in use, flowtype name
 *    already in use, unknown class id, illegal flowtype name, illegal
 *    type name, type name not unique within class, out of memory.
 *
 *    Use sksiteFlowtypeLookup() to get a flowtype ID given the
 *    flowtype name, use sksiteFlowtypeLookupByClassType() to get a
 *    flowtype ID given the class name and type name, and use
 *    sksiteFlowtypeLookupByClassIDType() to get a flowtype ID given
 *    the class ID and type name.
 *
 *    Use sksiteFlowtypeGetName() to get a flowtype name given the ID,
 *    use sksiteFlowtypeGetClassID() to get the class ID given a
 *    flowtype ID, sksiteFlowtypeGetClass() to get the class name
 *    given a flowtype ID, and sksiteFlowtypeGetType() to get the type
 *    name given a flowtype ID.
 *
 *    Use sksiteFlowtypeIterator() to view all created flowtypes.
 *
 *    Use sksiteClassFlowtypeIterator() to view all flowtypes on a
 *    specific class.
 *
 *    Use sksiteClassAddDefaultFlowtype() to mark a flowtype as a
 *    default for a class when fglobbing.
 */
int
sksiteFlowtypeCreate(
    sk_flowtype_id_t    flowtype_id,
    const char         *flowtype_name,
    sk_class_id_t       class_id,
    const char         *type_name);

/**
 *    Find the flowtype ID for a flowtype given its name.  Return
 *    SK_INVALID_FLOWTYPE if no flowtype is found with the given name.
 *
 *    Use sksiteFlowtypeLookupByClassType() to get a flowtype ID using
 *    the class name and type name.
 *
 *    Use sksiteFlowtypeGetName() to get a flowtype's name given its
 *    ID.
 *
 *    Use sksiteFlowtypeExists() to check whether a flowtype ID is
 *    known.
 */
sk_flowtype_id_t
sksiteFlowtypeLookup(
    const char         *flowtype_name);

/**
 *    Find the flowtype ID for a flowtype given its class name and
 *    type name.  Return SK_INVALID_FLOWTYPE if no flowtype is found
 *    with the given class and type.
 *
 *    Use sksiteFlowtypeLookup() to get a flowtype ID using the
 *    flowtype name.
 *
 *    See also sksiteFlowtypeLookupByClassIDType().
 */
sk_flowtype_id_t
sksiteFlowtypeLookupByClassType(
    const char         *class_name,
    const char         *type_name);

/**
 *    Find the flowtype ID for a flowtype given its class ID and type
 *    name.  Returns SK_INVALID_FLOWTYPE if no flowtype is found with
 *    the given class and type or if class_id is not known.
 *
 *    See also sksiteFlowtypeLookupByClassType() and
 *    sksiteFlowtypeLookup().
 */
sk_flowtype_id_t
sksiteFlowtypeLookupByClassIDType(
    sk_class_id_t       class_id,
    const char         *type_name);

/**
 *    Return 1 if a flowtype with the given ID exists, 0 if no such
 *    flowtype has been defined.
 *
 *    Use sksiteFlowtypeIterator() to visit all known flowtype IDs.
 */
int
sksiteFlowtypeExists(
    sk_flowtype_id_t    flowtype_id);

/**
 *    Return the maximum flowtype ID that has been allocated.  Return
 *    (sk_flowtype_id_t)(-1) if no flowtypes yet exist.
 *
 *    The caller may add one to this value to get the lowest ID that
 *    is certain not to have been allocated.
 *
 *    Note that not all IDs up to the maximum may have been allocated.
 */
sk_flowtype_id_t
sksiteFlowtypeGetMaxID(
    void);

/**
 *    Copy the class name of the flowtype with the given ID into the
 *    given buffer of size buffer_size.  If the name is longer than
 *    buffer_size, the value returned is truncated with a '\0' in the
 *    final position.
 *
 *    Return the number of characters that would have been written if
 *    the buffer had been long enough.  This length does not include
 *    the trailing '\0'.
 *
 *    A buffer one character longer than SK_MAX_STRLEN_FLOWTYPE is
 *    capable of holding all valid class names.
 *
 *    If 'flowtype_id' is SK_INVALID_FLOWTYPE or not known to the
 *    configuration file, the string "?" is copied into 'buffer'.  Use
 *    sksiteFlowtypeExists() to determine if a flowtype ID is known.
 *
 *    Use sksiteFlowtypeGetName() to get the name of the flowtype.
 *
 *    See also sksiteFlowtypeGetClassID() and sksiteFlowtypeGetType().
 */
int
sksiteFlowtypeGetClass(
    char               *buffer,
    size_t              buffer_size,
    sk_flowtype_id_t    flowtype_id);

/**
 *    Return the class ID of this flowtype's class.  Return
 *    SK_INVALID_CLASS if the flowtype does not exist.
 *
 *    Use sksiteFlowtypeGetClass() to get the class name for a
 *    flowtype ID.
 */
sk_class_id_t
sksiteFlowtypeGetClassID(
    sk_flowtype_id_t    flowtype_id);

/**
 *    Return the length of the longest currently known flowtype name,
 *    or a minimum value.  This result is suitable for choosing the
 *    size of a display column for flowtype names and/or IDs.
 *
 *    NOTE: This returns the length of the flowtype name.  To get the
 *    length of the longest type name, use
 *    sksiteFlowtypeGetMaxTypeStrLen().
 *
 *    The return value does not include the trailing '\0'.  See also
 *    SK_MAX_STRLEN_FLOWTYPE in silk_types.h.
 */
size_t
sksiteFlowtypeGetMaxNameStrLen(
    void);

/**
 *    Copy the name of the flowtype with the given ID into the given
 *    buffer of size buffer_size.  If the name is longer than
 *    buffer_size, the value returned is truncated with a '\0' in the
 *    final position.
 *
 *    Return the number of characters that would have been written if
 *    the buffer had been long enough.  This length does not include
 *    the trailing '\0'.
 *
 *    A buffer one character longer than SK_MAX_STRLEN_FLOWTYPE is
 *    capable of holding all valid flowtype names.
 *
 *    If 'flowtype_id' is SK_INVALID_FLOWTYPE, the string "?" is
 *    copied into 'buffer'.  If 'flowtype_id' is not known to the
 *    configuration file (that is, it does not have a name), put the
 *    numeric ID into 'buffer'.  Use sksiteFlowtypeExists() to
 *    determine if a flowtype ID is known.
 *
 *    Use sksiteFlowtypeLookup() to get a flowtype ID given a flowtype
 *    name.
 *
 *    Use sksiteFlowtypeGetClass() and sksiteFlowtypeGetType() to get
 *    the class name and type name given a flowtype ID.
 */
int
sksiteFlowtypeGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_flowtype_id_t    flowtype_id);

/**
 *    Return the length of the longest currently known flowtype type,
 *    or a minimum value.  This result is suitable for choosing the
 *    size of a display column for flowtype types.
 *
 *    NOTE: This returns the length of the type name.  To get the
 *    length of the longest flowtype name, use
 *    sksiteFlowtypeGetMaxNameStrLen().
 *
 *    The return value does not include the trailing '\0'.  See also
 *    SK_MAX_STRLEN_FLOWTYPE in silk_types.h.
 */
size_t
sksiteFlowtypeGetMaxTypeStrLen(
    void);

/**
 *    Copy the type name of the flowtype with the given ID into the
 *    given buffer of size buffer_size.  If the name is longer than
 *    buffer_size, the value returned is truncated with a '\0' in the
 *    final position.
 *
 *    Return the number of characters that would have been written if
 *    the buffer had been long enough.  This length does not include
 *    the trailing '\0'.
 *
 *    A buffer one character longer than SK_MAX_STRLEN_FLOWTYPE is
 *    capable of holding all valid flowtype names.
 *
 *    If 'flowtype_id' is SK_INVALID_FLOWTYPE or not known to the
 *    configuration file, put the numeric ID into 'buffer'.  Use
 *    sksiteFlowtypeExists() to determine if a flowtype ID is known.
 *
 *    Use sksiteFlowtypeGetName() to get the name of the flowtype.
 *
 *    See also sksiteFlowtypeGetClass().
 */
int
sksiteFlowtypeGetType(
    char               *buffer,
    size_t              buffer_size,
    sk_flowtype_id_t    flowtype_id);

/**
 *    Set iter to be an iterator that loops over all defined
 *    flowtypes.  Use sksiteFlowtypeIteratorNext() to visit each
 *    flowtype ID.
 */
void
sksiteFlowtypeIterator(
    sk_flowtype_iter_t *iter);

/**
 *    Assert that the given flowtype exists and is associated with the
 *    given class name and class type name.  If this is not the case,
 *    an error message is printed and the program abort()s.  The
 *    'pack_logic_file' is the path to the file doing the assertion.
 */
void
sksiteFlowtypeAssert(
    const char         *pack_logic_file,
    sk_flowtype_id_t    flowtype_id,
    const char         *class_name,
    const char         *type);


/** Paths *************************************************************/

/**
 *    Return the default value for the data root directory that was
 *    specified when SiLK was built.
 *
 *    This function ignores any environment settings, and it should
 *    only be used to get the default.  This function may be called
 *    without initializing the site.
 */
const char *
sksiteGetDefaultRootDir(
    void);


/**
 *    Fill 'buffer' with the data root directory.  'buffer' is a
 *    character array whose length is 'bufsize'.  Returns a pointer to
 *    'buffer', or NULL if 'buffer' is too small to hold the root
 *    directory.
 */
char *
sksiteGetRootDir(
    char               *buffer,
    size_t              bufsize);

/**
 *    Sets the data root directory to 'rootdir', overriding the value
 *    that was set when SiLK was configured.  Returns 0 on success, or
 *    -1 if 'rootdir' is NULL, the empty string, or longer than
 *    PATH_MAX characters.
 */
int
sksiteSetRootDir(
    const char         *rootdir);

/**
 *    Sets the path format for output files, overriding the current
 *    value.  Returns 0 on success, or -1 if 'format' is NULL, the
 *    empty string, or longer than PATH_MAX characters.
 *
 *    NOTE: At the moment, all path formats are required to end in %x,
 *    so that filenames have the default format.  This restriction may
 *    be lifted in the future.
 *
 *    The following strings have special meaning in path formats:
 *
 *     %C - Class name
 *     %F - Flowtype name
 *     %H - Hour, two digits, zero-padded
 *     %N - Sensor name
 *     %T - Type name
 *     %Y - Year, four digits, zero-padded
 *     %d - Day of month, two digits, zero-padded
 *     %f - Flowtype ID
 *     %m - Month of year, two digits, zero-padded
 *     %n - Sensor ID
 *     %x - Default filename, which is the same as "%F-%N_%Y%m%d.%H"
 *     %% - a single percent sign
 *
 *    The default path format is "%T/%Y/%m/%d/%x"
 */
int
sksiteSetPathFormat(
    const char         *format);


/**
 *    Fill 'buffer' with the path to the packing logic file.  'buffer'
 *    is a character array whose length is 'bufsize'.  Returns NULL if
 *    the packing-logic path was not set.  Otherwise, returns a
 *    pointer to 'buffer', or NULL if 'buffer' is too small to hold
 *    the value.
 */
char *
sksiteGetPackingLogicPath(
    char               *buffer,
    size_t              bufsize);


/**
 *    Set the packing-logic value to 'pathname'.  The packer,
 *    rwflowpack, may use this value to determine into which class and
 *    type a flow belongs.  Return 0 on success, or -1 on failure.
 */
int
sksiteSetPackingLogicPath(
    const char         *pathname);


/**
 *    Fill in 'buffer', a C-array of size 'bufsize', with the complete
 *    path of the file having the specified 'flowtype_id',
 *    'sensor_id', and 'timestamp'.  The name will be of the form
 *    specified by the current path format.
 *
 *    When 'suffix' is non-NULL and not the empty string, it will be
 *    appended to the name of the generated file.  If 'suffix' does
 *    not begin with a period ("."), one will be added between the
 *    filename and the suffix.
 *
 *    When 'reldir_begin' is non-NULL, its value is set to the
 *    beginning of the relative directory; i.e., to the character
 *    following the '/' that ends the root-directory.  For the default
 *    path format of "%T/%Y/%m/%d/%x", 'reldir_begin' would point to
 *    the start of the type name (%T).
 *
 *    When 'filename_begin' is non-NULL, its value is set to the
 *    beginning of the filename; i.e., to the character following the
 *    final '/'.
 *
 *    Return a pointer to 'buffer' or NULL on error.
 */
char *
sksiteGeneratePathname(
    char               *buffer,
    size_t              bufsize,
    sk_flowtype_id_t    flowtype,
    sk_sensor_id_t      sensor,
    sktime_t            timestamp,
    const char         *suffix,
    char              **reldir_begin,
    char              **filename_begin);


/**
 *    Extract the flowtype, sensor, and timestamp from 'filename', the
 *    name of or a path to a SiLK Flow file in the "%x" format, and
 *    put the values into 'out_flowtype', 'out_sensor' and
 *    'out_timestamp', respectively.  Any of those values may be NULL,
 *    indicating that the caller does not want the value returned.
 *    The function returns the flowtype, or SK_INVALID_FLOWTYPE if the
 *    name is not in the proper form or if the flowtype is not
 *    recognized.  An unrecognized sensor name is allowed.
 *
 *    The standard format for the name of a SiLK flow file is:
 *
 *    flowtypeString-SensorName_YYYYMMDD.HH[.*]
 *
 *    with a hyphen separating the flowtype from the sensor, and an
 *    underscore separating the sensor from the time.  The filename
 *    may include a suffix made up of a period and additional text.
 *    When 'filename' has a suffix and 'out_suffix' is non-NULL,
 *    'out_suffix' will be set to the location of the '.' in
 *    'filename' that begins the suffix.
 *
 *    The function will take the basename of 'filename', so 'filename'
 *    may include directory components.
 *
 */
sk_flowtype_id_t
sksiteParseFilename(
    sk_flowtype_id_t   *out_flowtype,
    sk_sensor_id_t     *out_sensor,
    sktime_t           *out_timestamp,
    const char        **out_suffix,
    const char         *filename);

/**
 *    Extract the flowtype, sensor, and timestamp from 'filename', the
 *    name of a SiLK Flow file, and use those values to fill in
 *    'buffer', a C-array of size 'bufsize', with the complete path of
 *    the file having that flowtype, sensor, and timestamp.
 *
 *    Returns a pointer to 'buffer' on success, or NULL if an error
 *    occurs or if the filename is not of the expected form.
 *
 *    When 'suffix' is NULL and 'filename' has a suffix, the path name
 *    put into 'buffer' will have the same suffix appended.  To have
 *    the suffix removed from the new path, pass in the empty string
 *    as the value of 'suffix'.
 *
 *    The parameters 'buffer' and 'filename' may point to the same
 *    location.
 *
 *    This function works as a convenience wrapper around
 *    sksiteParseFilename() and sksiteGeneratePathname().  See the
 *    documentation of those functions for additional information.
 */
char *
sksiteParseGeneratePath(
    char               *buffer,
    size_t              bufsize,
    const char         *filename,
    const char         *suffix,
    char              **reldir_begin,
    char              **filename_begin);

/** Error Reporting Types/Functions************************************/

/**
 *    Several functions declared in this header create and fill an
 *    sksite_error_iterator_t object---an "error iterator"---when they
 *    encounter errors parsing or validating a list of entries.
 *
 *    The caller passes the address of an sksite_error_iterator_t* to
 *    these functions.  On success, the iterator is unchanged.  When
 *    certain errors occur, an iterator is created at the specified
 *    location and it is filled with the errors that occurred while
 *    validating or parsing each entry.
 *
 *    The caller uses sksiteErrorIteratorNext() to visit each error.
 *    For each error the caller may call the following functions:
 *
 *      sksiteErrorIteratorGetCode() returns the error code which is
 *      one of the values in defined by sksite_validate_enum_t.
 *
 *      sksiteErrorIteratorGetToken() returns the individual entry
 *      that caused the error.
 *
 *      sksiteErrorIteratorGetMessage() returns an error message.
 *      This message includes the token that caused the error.
 *
 *    When finished with the iterator, the caller must call
 *    sksiteErrorIteratorFree() to free the memory associated with the
 *    iterator.
 */
typedef struct sksite_error_iterator_st sksite_error_iterator_t;

/**
 *    Possible errors that may arise when parsing or validating a
 *    Sensor, Class, Type, or Flowtype.
 */
typedef enum sksite_validate_enum_en {
    /** No delimiter present in class/type pair */
    SKSITE_ERR_FLOWTYPE_NO_DELIM,
    /** Class/type pair has unknown class name */
    SKSITE_ERR_FLOWTYPE_UNKNOWN_CLASS,
    /** The "all/type" pair has unknown type name */
    SKSITE_ERR_FLOWTYPE_UNKNOWN_TYPE,
    /** Class/type pair has unknown type for given class */
    SKSITE_ERR_FLOWTYPE_TYPE_NOT_IN_CLASS,
    /** Unknown sensor name */
    SKSITE_ERR_UNKNOWN_SENSOR,
    /** Unknown sensor numeric id */
    SKSITE_ERR_UNKNOWN_SENSOR_ID,
    /** Unknown type for given class */
    SKSITE_ERR_TYPE_NOT_IN_CLASSES,
    /** Sensor not available in given class(es) */
    SKSITE_ERR_SENSOR_NOT_IN_CLASSES,
    /** Class name is unknown */
    SKSITE_ERR_CLASS_UNKNOWN,
    /** Class name is unknown */
    SKSITE_ERR_TYPE_UNKNOWN,
    /** Site file does not name a default class */
    SKSITE_ERR_CLASS_NO_DEFAULT,
    /** Sensorgroup name is unknown */
    SKSITE_ERR_SENSORGROUP_UNKNOWN,
    /** Token exceeds maximum class/type/sensor/flowtype length */
    SKSITE_ERR_LONG_TOKEN = 64,
    /** The file name in an @@\FILE construct exceeds PATH_MAX */
    SKSITE_ERR_LONG_FILE,
    /** Token contains an '@' without an '@' at the start. */
    SKSITE_ERR_BAD_FILE_BEGIN,
    /** Token contains an unknown @@\X escape */
    SKSITE_ERR_BAD_ESCAPE,
    /** Error opening or reading the file named by @@\FILE */
    SKSITE_ERR_FILE_IO,
    /** An @@\FILE may not use @@ syntax */
    SKSITE_ERR_FILE_RECURSE,
    /** Error parsing numeric sensor id or range */
    SKSITE_ERR_UTILS_OFFSET = 255
} sksite_validate_enum_t;


/**
 *    Moves the iterator 'iter' to the next error or initializes the
 *    iterator returned by sksiteValidateFlowtypes() or
 *    sksiteValidateSensors().
 *
 *    The function returns SK_ITERATOR_OK if there are more errors, or
 *    SK_ITERATOR_NO_MORE_ENTRIES if all errors have been seen.
 */
int
sksiteErrorIteratorNext(
    sksite_error_iterator_t    *iter);


/**
 *    Frees all memory associated with the iterator 'iter'.
 *    Does nothing if 'iter' is NULL.
 */
void
sksiteErrorIteratorFree(
    sksite_error_iterator_t    *iter);


/**
 *    Resets the iterator 'iter' so that the errors may be iterated
 *    over again.
 */
void
sksiteErrorIteratorReset(
    sksite_error_iterator_t    *iter);


/**
 *    Returns the error code associated with the error at the current
 *    position of the iterator 'iter'.  The error code is a value from
 *    sksite_validate_enum_t.  This function does not advance the
 *    iterator.
 */
int
sksiteErrorIteratorGetCode(
    const sksite_error_iterator_t  *iter);


/**
 *    Changed in SiLK 3.20.0 to return the same value as
 *    sksiteErrorIteratorGetMessage().
 *
 *    Its previous behavior was:
 *
 *    Returns the current token---that is, the class/type pair or the
 *    sensor that was found to be invalid.  This token is a pointer
 *    into the character pointer array that was passed to
 *    sksiteValidateFlowtypes() or sksiteValidateSensors().  This
 *    function does not advance the iterator.
 */
const char *
sksiteErrorIteratorGetToken(
    const sksite_error_iterator_t  *iter);


/**
 *    Returns a message explaining the current error.  The message
 *    will include the token---that is, the class/type pair or the
 *    sensor that was found to be invalid.  This function does not
 *    advance the iterator.
 */
const char *
sksiteErrorIteratorGetMessage(
    const sksite_error_iterator_t  *iter);



/** Special Support Functions *****************************************/


/**
 *    Treats 'ft_name_list' as a comma separated list of tokens
 *    representing "class/type" pairs---where a slash('/') separates
 *    the class and type---and appends to 'ft_vector' the numeric
 *    sk_flowtype_id_t of each class/type pair that was found.
 *
 *    As of SiLK 3.20.0, the special token "@FILE" tells the library to read
 *    tokens from the file 'FILE'.  The "FILE" string may contain escapes "@,"
 *    meaning "," and "@@" meaning "@".  Note that this has the potential to
 *    interfere with the default_classes_token.  In particular, if
 *    default_classes_token is @, there is no way to distinguish "@/in" as
 *    "use the 'in' type from the default class" and "read values from the
 *    file '/in'".
 *
 *    When the 'all_classes_token' is not NULL and a parsed "class"
 *    matches this string, the specified "type" is checked for in all
 *    classes.  An error is added to 'out_error_iter' if "type" is not
 *    valid for any class.
 *
 *    When the 'all_types_token' is not NULL and a parsed "type"
 *    matches this string, all types are appended to 'ft_vector' for
 *    the specified "class".
 *
 *    When the 'default_classes_token' is not NULL and a parsed
 *    "class" matches this string, the specified "type" is checked for
 *    in the default class.  An error is added to 'out_error_iter' if
 *    the silk.conf file does not specify a default class or when
 *    "type" is not valid for this class.
 *
 *    When the 'default_types_token' is not NULL and a parsed "type"
 *    matches this string, the default types are appended to
 *    'ft_vector' for the specified "class".
 *
 *    Creates a new error iterator when 'out_error_iter' is not NULL
 *    and an error must be reported.  Any previous error iterator in
 *    that location is lost.
 *
 *    Appends an error to 'out_error_iter' when the "class/type" pair
 *    is invalid or does not have the necessary delimiter.
 *
 *    The values are appended to 'ft_vector' in the order which they
 *    appear in the list, though duplicate values are not added to the
 *    vector.  Values in 'ft_vector' when the function was called
 *    ramain in place and are ignored by this function.
 *
 *    Returns 0 and does not fill 'out_error_iter' on success.
 *    Returns 0 and does not modify the 'ft_vector' or the
 *    'out_error_iter' when 'ft_name_list' is the empty string or
 *    contains only commas.
 *
 *    Returns -1 and does not fill 'out_error_iter' for the following
 *    conditions: when 'ft_vector' or 'ft_name_list' is NULL, when the
 *    element size of 'ft_vector' is not sizeof(sk_flowtype_id_t), and
 *    when a memory allocation error occurs.
 *
 *    Returns a positive value and fills 'out_error_iter' (if not
 *    NULL) when one or more tokens are found that are not valid
 *    class/type pairs.  The return value is the number of invalid
 *    tokens found.
 *
 *    Since SiLK 3.11.0.
 */
int
sksiteParseFlowtypeList(
    sk_vector_t                *ft_vector,
    const char                 *ft_name_list,
    const char                 *all_classes_token,
    const char                 *all_types_token,
    const char                 *default_class_token,
    const char                 *default_types_token,
    sksite_error_iterator_t   **out_error_iter);

/**
 *    Treats 'class_name_list' as a comma separated list of tokens
 *    representing class names and appends to 'class_vector' the
 *    numeric sk_class_id_t of each class that was found.
 *
 *    As of SiLK 3.20.0, the special token "@FILE" tells the library to read
 *    tokens from the file 'FILE'.  The "FILE" string may contain escapes "@,"
 *    meaning "," and "@@" meaning "@".
 *
 *    When the 'all_classes_token' is not NULL and a parsed class
 *    matches this string, all sk_class_id_t's are added to
 *    'class_vector'.
 *
 *    When the 'default_classes_token' is not NULL and a parsed class
 *    matches this string, the ID of the default class is added to
 *    'class_vector'.  An error is added to 'out_error_iter' if the
 *    silk.conf file does not specify a default class.
 *
 *    Creates a new error iterator when 'out_error_iter' is not NULL
 *    and an error must be reported.  Any previous error iterator in
 *    that location is lost.
 *
 *    Appends an error to 'out_error_iter' when the class is not
 *    recognized as a class name.
 *
 *    The values are appended to 'class_vector' in the order which
 *    they appear in the list, though duplicate values are not added
 *    to the vector.  Values in 'class_vector' when the function was
 *    called remain in place and are ignored by this function.
 *
 *    Returns 0 and does not fill 'out_error_iter' on success.
 *    Returns 0 and does not modify the 'class_vector' or the
 *    'out_error_iter' when 'class_name_list' is the empty string or
 *    contains only commas.
 *
 *    Returns -1 and does not fill 'out_error_iter' for the following
 *    conditions: when 'class_vector' or 'class_name_list' is NULL,
 *    when the element size of 'class_vector' is not
 *    sizeof(sk_class_id_t), and when a memory allocation error
 *    occurs.
 *
 *    Returns a positive value and fills 'out_error_iter' (if not
 *    NULL) when one or more tokens are found that are not valid class
 *    names.  The return value is the number of invalid tokens found.
 *
 *    Since SiLK 3.11.0.
 */
int
sksiteParseClassList(
    sk_vector_t                *class_vector,
    const char                 *class_name_list,
    const char                 *all_classes_token,
    const char                 *default_class_token,
    sksite_error_iterator_t   **out_error_iter);

/**
 *    Treats 'type_name_list' as a comma separated list of tokens
 *    representing type names for one or more of the sk_class_id_t's
 *    specified in the 'classes_vector' and appends to 'ft_vector' the
 *    numeric sk_flowtype_id_t of each type that was found.
 *
 *    As of SiLK 3.20.0, the special token "@FILE" tells the library to read
 *    tokens from the file 'FILE'.  The "FILE" string may contain escapes "@,"
 *    meaning "," and "@@" meaning "@".
 *
 *    When the 'all_types_token' is not NULL and a parsed "type"
 *    matches this string, all types are appended to 'ft_vector' for
 *    each class specified in 'classes_vector'.
 *
 *    When the 'default_types_token' is not NULL and a parsed "type"
 *    matches this string, the default types are appended to
 *    'ft_vector' for each class specified in 'classes_vector'.
 *
 *    Creates a new error iterator when 'out_error_iter' is not NULL
 *    and an error must be reported.  Any previous error iterator in
 *    that location is lost.
 *
 *    Appends an error to 'out_error_iter' when the type is not
 *    recognized as a type name in any of the classes.
 *
 *    The values are appended to 'ft_vector' in the order which they
 *    appear in the list, though duplicate values are not added to the
 *    vector.  Values in 'ft_vector' when the function was called
 *    remain in place and are ignored by this function.
 *
 *    Returns 0 and does not fill 'out_error_iter' on success.
 *    Returns 0 and does not modify the 'ft_vector' or the
 *    'out_error_iter' when 'type_name_list' is the empty string or
 *    contains only commas.
 *
 *    Returns -1 and does not fill 'out_error_iter' for the following
 *    conditions: when 'ft_vector', 'type_name_list', or
 *    'classes_vector' is NULL, when the element size of 'ft_vector'
 *    is not sizeof(sk_flowtype_id_t), when the element size of
 *    'classes_vector' is not sizeof(sk_class_id_t), and when a memory
 *    allocation error occurs.
 *
 *    Returns a positive value and fills 'out_error_iter' (if not
 *    NULL) when one or more tokens are found that are not valid type
 *    names for at least one of the sk_class_id_t's specifed in
 *    'classes_vector'.  The return value is the number of invalid
 *    tokens found.
 *
 *    Since SiLK 3.11.0.
 */
int
sksiteParseTypeList(
    sk_vector_t                *ft_vector,
    const char                 *type_name_list,
    const sk_vector_t          *class_vector,
    const char                 *all_types_token,
    const char                 *default_type_token,
    sksite_error_iterator_t   **out_error_iter);


/**
 *    Flag for sksiteParseSensorList() indicating the parser should accept
 *    sensor IDs in addition to sensor names.  Ranges of sensor IDs are not
 *    allowed.
 *
 *    Since SiLK 3.21.0
 */
#define SKSITE_SENSORS_ALLOW_ID      0x01

/**
 *    Flag for sksiteParseSensorList() indicating the parser should accept
 *    sensor IDs and ranges of sensor IDs in addition to sensor names.
 *
 *    Since SiLK 3.21.0
 */
#define SKSITE_SENSORS_ALLOW_RANGE   0x02

/**
 *    Flag for sksiteParseSensorList() indicating the parser should accept
 *    sensorgroups defined in the silk.conf file.
 *
 *    Since SiLK 3.21.0
 */
#define SKSITE_SENSORS_ALLOW_GROUP   0x04

/**
 *    Treats `sensor_name_list` as a comma separated list of tokens
 *    representing sensor names (and perhaps additional values as indicated by
 *    `flags`) and appends to `sensor_vector` the numeric sk_sensor_id_t of
 *    each sensor that was found.
 *
 *    As of SiLK 3.20.0, the special token "@FILE" tells the library to read
 *    tokens from the file 'FILE'.  The "FILE" string may contain escapes "@,"
 *    meaning "," and "@@" meaning "@".
 *
 *    When the `flags` value is 0, the function rejects any token that is not
 *    a sensor name.  Enabling the parsing of additional tokens may be enabled
 *    by setting `flags`:
 *
 *      When the `flags & SKSITE_SENSORS_ALLOW_ID` is non-zero, the function
 *      allows sensor names and numeric sensor IDs.
 *
 *      When the `flags & SKSITE_SENSORS_ALLOW_RANGE` value is non-zero, the
 *      function allows sensor names, numeric sensor IDs, and ranges of IDs.
 *
 *      When `flags & SKSITE_SENSORS_ALLOW_GROUP` is non-zero, the function
 *      allows sensor-groups defined in the silk.conf file to be recognized.
 *
 *    The tokens in `sensor_name_list` are checked in this order: (1)as the
 *    name of a sensor, (2)as the `all_sensors_token` if non-NULL, (3)as the
 *    name of a sensor-group, (4)as a sensor-id or a range of sensor-ids.
 *
 *    When `classes_vector` is not NULL, it must be a vector of
 *    sk_class_id_t's.  The function appends an error to `out_error_iter` when
 *    it parses a sensor name or ID that does not belong to one of the
 *    specified classes.
 *
 *    When the `all_sensors_token` is not NULL and a parsed sensor matches
 *    this string, all sk_sensor_id_t's are added to `sensor_vector` (perhaps
 *    limited to all sensors in the specified sk_class_id_t's).
 *
 *    Creates a new error iterator when `out_error_iter` is not NULL and an
 *    error must be reported.  Any previous error iterator in that location is
 *    lost.
 *
 *    Appends an error to `out_error_iter` when the sensor is not recognized
 *    as a sensor name, is not a valid sensor ID, or is not a member at least
 *    one of the classes specified in `classes_vector`.  When ranges are
 *    allowed, the starting and ending point of the range must be valid but
 *    interior sensor IDs need not exist; however, if they do exist, they must
 *    be a member of the classes specified in `classes_vector`.
 *
 *    The values are appended to `sensor_vector` in the order which they
 *    appear in the list, though duplicate values appearing in
 *    `sensor_name_list` are not added to the vector.  Values in
 *    `sensor_vector` when the function was called remain in place and are
 *    ignored by this function.
 *
 *    Returns 0 and does not fill `out_error_iter` on success.  Returns 0 and
 *    does not modify the `sensor_vector` or the `out_error_iter` when
 *    `sensor_name_list` is the empty string or contains only commas.
 *
 *    Returns -1 and does not fill `out_error_iter` for the following
 *    conditions: when `sensor_vector` or `sensor_name_list` is NULL, when the
 *    element size of `sensor_vector` is not sizeof(sk_sensor_id_t), when
 *    `classes_vector` is provided and its element size is not
 *    sizeof(sk_class_id_t), and when a memory allocation error occurs.
 *
 *    Returns a positive value and fills `out_error_iter` (if not NULL) when
 *    one or more tokens are found that are not valid sensor names, sensor
 *    IDs, sensor ranges, or a member of the sk_class_id_t's specifed in
 *    `classes_vector`.  The return value is the number of invalid tokens
 *    found.
 *
 *    Since SiLK 3.11.0.  Changed in SiLK 3.20.0 to accept "@FILE" tokens.
 *    Changed in SiLK 3.21.0 to support sensor-group names.
 */
int
sksiteParseSensorList(
    sk_vector_t                *sensor_vector,
    const char                 *sensor_name_list,
    const sk_vector_t          *classes_vector,
    const char                 *all_sensors_token,
    unsigned int                flags,
    sksite_error_iterator_t   **out_error_iter);

/**
 *    Treats 'group_name_list' as a comma separated list of tokens
 *    representing sensor-group names and appends to 'group_vector' the
 *    numeric sk_sensorgroup_id_t of each sensor-group that was found.
 *
 *    The special token "@FILE" tells the library to read tokens from the file
 *    'FILE'.  The "FILE" string may contain escapes "@," meaning "," and "@@"
 *    meaning "@".
 *
 *    Creates a new error iterator when 'out_error_iter' is not NULL and an
 *    error must be reported.  Any previous error iterator in that location is
 *    lost.
 *
 *    Appends an error to 'out_error_iter' when the group is not recognized as
 *    a sensor-group name.
 *
 *    The values are appended to 'group_vector' in the order which they appear
 *    in the list, though duplicate values are not added to the vector.
 *    Values in 'group_vector' when the function was called remain in place
 *    and are ignored by this function.
 *
 *    Returns 0 and does not fill 'out_error_iter' on success.  Returns 0 and
 *    does not modify the 'group_vector' or the 'out_error_iter' when
 *    'group_name_list' is the empty string or contains only commas.
 *
 *    Returns -1 and does not fill 'out_error_iter' for the following
 *    conditions: when 'group_vector' or 'group_name_list' is NULL, when the
 *    element size of 'group_vector' is not sizeof(sk_sensorgroup_id_t), and
 *    when a memory allocation error occurs.
 *
 *    Returns a positive value and fills 'out_error_iter' (if not NULL) when
 *    one or more tokens are found that are not valid sensor-group names.  The
 *    return value is the number of invalid tokens found.
 *
 *    Since SiLK 3.21.0.
 */
int
sksiteParseSensorgroupList(
    sk_vector_t                *group_vector,
    const char                 *group_name_list,
    sksite_error_iterator_t   **out_error_iter);


/**
 *    Validate the class/type pairs specified in the character pointer
 *    array 'ft_strings'.  Each value in the array should contain a
 *    valid class name and type name, with the names separated by the
 *    character 'delim'.  The class name and/or the type name may be
 *    "all".
 *
 *    If 'ft_count' is non-negative, it is used as the number of
 *    entries in 'ft_strings'.  If 'ft_count' is negative,
 *    'ft_strings' is treated a NULL-terminated array.
 *
 *    The valid flowtype IDs are appended to the 'ft_vec' vector,
 *    unless the flowtype ID is already present in 'ft_vec'.
 *
 *    If 'error_iter' is non-NULL and an invalid class/type pair is
 *    encountered, a new sksite_error_iterator_t is allocated at the
 *    specified location, and an appropriate error code is added to
 *    the iterator.  The caller must invoke sksiteErrorIteratorFree()
 *    to free the iterator.
 *
 *    The function returns 0 if all flowtypes were valid.  A return
 *    value of -1 indicates invalid input---for example, 'ft_vec'
 *    elements are not the correct size. A positive return value
 *    indicates the number of invalid class/type pairs.
 */
int
sksiteValidateFlowtypes(
    sk_vector_t                *flowtypes_vec,
    int                         flowtype_count,
    const char                **flowtype_strings,
    char                        delimiter,
    sksite_error_iterator_t   **error_iter);


/**
 *    Validate the sensor names and/or sensor IDs listed in the
 *    character pointer array 's_strings'.  Each value in the array
 *    should contain a valid sensor name or a valid sensor numeric ID.
 *
 *    If 's_count' is non-negative, it is used as the number of
 *    entries in 's_strings'.  If 's_count' is negative, 's_strings'
 *    is treated a NULL-terminated array.
 *
 *    The valid sensor IDs are appended to the 's_vec' vector,
 *    unless the sensor ID is already present in 's_vec'.
 *
 *    If 'ft_vec' is non-NULL, it should point to a vector containing
 *    flowtype IDs, and only sensors that exist in the specified
 *    flowtypes will be added to 's_vec'.  Other sensors are treated
 *    as invalid.
 *
 *    If 'error_iter' is non-NULL and an invalid sensor is
 *    encountered, a new sksite_error_iterator_t is allocated at the
 *    specified location, and an appropriate error code is added to
 *    the iterator, along with a pointer into the 's_strings' array.
 *    The caller must ensure that entries in the 's_strings' array
 *    remain valid while iterating over the errors.  The caller must
 *    invoke sksiteErrorIteratorFree() to free the iterator.
 *
 *    The function returns 0 if all sensors were valid.  A return
 *    value of -1 indicates invalid input---for example, 's_vec'
 *    elements are not the correct size. A positive return value
 *    indicates the number of invalid sensors.
 */
int
sksiteValidateSensors(
    sk_vector_t                *sensors_vec,
    const sk_vector_t          *flowtypes_vec,
    int                         sensor_count,
    const char                **sensor_strings,
    sksite_error_iterator_t   **invalid_sensors_vec);


/**
 *    Parse 'start_time_str' and 'end_time_str' as the starting and
 *    ending datetimes of a range of files to request from the SiLK
 *    data repository and fill 'start_time' and 'end_time' with the
 *    datetimes.
 *
 *    When both 'start_time_str' and 'end_time_str' are NULL, the time
 *    window is set from midnight today to the current hour.
 *
 *    When 'start_time_str' is NULL and 'end_time_str' is not, the
 *    function returns -1 and no parameters are modified.
 *
 *    When 'start_time_str' is given and 'end_time_str' is NULL, the
 *    time window is set either to that entire day when
 *    'start_time_str' is to day precision or to a single hour when
 *    the precision is to the hour or higher or the time is specified
 *    in UNIX epoch seconds.
 *
 *    When 'start_time_str' and 'end_time_str' are both given, the
 *    time window is determined as described in the rwfglob and
 *    rwfilter manual pages.  Return -3 when the end_time is earlier
 *    than the start_time.
 *
 *    Return 1 when 'start_time_str' is provided and cannot be parsed
 *    as a datetime to at least day precision or as UNIX epoch
 *    seconds.  If 'error_code' is not NULL, the error returned by
 *    skStringParseDatetime() is stored in the location it references.
 *
 *    Return 2 when 'end_time_str' is provided and cannot be parsed as
 *    a datetime to at least day precision or as UNIX epoch seconds.
 *    If 'error_code' is not NULL, the error returned by
 *    skStringParseDatetime() is stored in the location it references.
 *
 *    Return -1 when 'start_time_str' is NULL and 'end_time_str' is
 *    not.
 *
 *    Return -3 when the 'end_time' is earlier than the 'start_time'.
 *    The parsed times are stored in 'start_time' and 'end_time'.
 *
 *    Since SiLK 3.11.0.
 */
int
sksiteRepoIteratorParseTimes(
    sktime_t           *start_time,
    sktime_t           *end_time,
    const char         *start_time_str,
    const char         *end_time_str,
    int                *error_code);



/** DATA_ROOTDIR Repository Iteration (fglob) *************************/

typedef struct sksite_repo_iter_st sksite_repo_iter_t;

typedef struct sksite_fileattr_st {
    sktime_t            timestamp;
    sk_sensor_id_t      sensor;
    sk_flowtype_id_t    flowtype;
    /* debating whether to include a uint32_t here for "user_data".
     * On 64bit platform, the struct will be padded by an additional 4
     * bytes regardless.  The additional value could be used as a
     * record offset if we ever wanted to provide a pointer to an
     * individual record in a file, or it could be used for
     * information about the location of the file. */
} sksite_fileattr_t;


#define RETURN_MISSING (1 << 0)


/**
 *    Create a new iterator that will return files from the data
 *    store.  The iterator will be created at the location specified
 *    by 'iter'.
 *
 *    Each file in the data store is located by a triple comprised of
 *    the flowtype, sensor, and start-hour.  The list of flowtypes to
 *    iterate over is specified by 'ft_vec', a vector containing
 *    sk_flowtype_id_t's.  The list of sensors to iterate over is
 *    specified by 'sen_vec', a vector containing sk_sensor_id_t's.  If
 *    'sen_vec' is NULL, the iterator uses all sensors that are valid
 *    for the given flowtypes.  The time range to iterate over is
 *    specified by 'start_time' to 'end_time'.
 *
 *    This function makes no effort to ensure that the values in
 *    'ft_vec' and 'sen_vec' are unique.  Duplicate values in those
 *    arrays will cause a file to be visited multiple times.
 *
 *    'flags' contain addition information.  Normally, the iterator
 *    does not return files that do not exist in the repository.
 *    However, when RETURN_MISSING is set in 'flags', the iterator
 *    will return missing files in addition to existing files.
 *
 *    This function returns 0 on success, or -1 for failure.  Failures
 *    include: 'iter' being NULL; 'ft_vec' being NULL or having the
 *    wrong sized elements; 'sen_vec' having the wrong sized elements;
 *    'end_time' less than 'start_time'; memory allocation error.
 *
 *    The caller may use any combination of
 *    sksiteRepoIteratorGetFileattrs(),
 *    sksiteRepoIteratorRemainingFileattrs(), or the various
 *    sksiteRepoIteratorNext*() functions to iterate over the files.
 *    Note that each call to one of these functions moves the
 *    iterator.
 *
 *    The caller should use 'sksiteRepoIteratorDestroy()' to destroy
 *    the iterator once she has finished with the iterator.
 */
int
sksiteRepoIteratorCreate(
    sksite_repo_iter_t    **iter,
    const sk_vector_t      *flowtypes_vec,
    const sk_vector_t      *sensor_vec,
    sktime_t                start_time,
    sktime_t                end_time,
    uint32_t                flags);


/**
 *    Destroy an iterator created by sksiteRepoIteratorCreate(), and
 *    set 'iter' to NULL.  The function is a no-op if 'iter' or
 *    '*iter' is NULL.
 */
void
sksiteRepoIteratorDestroy(
    sksite_repo_iter_t    **iter);


/**
 *    Fill 'attr_array' with the next 'max_count' file attributes read
 *    from the iterator 'iter'.  Return the number of file attributes
 *    added to 'attr_array'.  A number less than 'max_count' indicates
 *    all files have been iterated over.
 *
 *    This function does not provide any mechanism for the caller to
 *    determine whether an entry in the 'attr_array' represents a
 *    missing file, when 'iter' is iterating over missing files.
 */
size_t
sksiteRepoIteratorGetFileattrs(
    sksite_repo_iter_t *iter,
    sksite_fileattr_t  *attr_array,
    size_t              attr_max_count);

/**
 *    Put the file attributes of the next file from the data store
 *    into the location specified by 'file_attr'.  If 'is_missing' is
 *    not-NULL, it will be set to 0 if the file exists in the data
 *    store, or 1 if the file is missing from the data store.
 *
 *    Return SK_ITERATOR_OK when a file exists, or
 *    SK_ITERATOR_NO_MORE_ENTRIES when the iterator has visited all
 *    files.
 */
int
sksiteRepoIteratorNextFileattr(
    sksite_repo_iter_t *iter,
    sksite_fileattr_t  *fileattr,
    int                *is_missing);

/**
 *    Put the file path of the next file from the data store into the
 *    location specified by 'path'.  The value 'path_len' should
 *    indicate the number of characters 'path' can hold.  If
 *    'is_missing' is not-NULL, it will be set to 0 if the file exists
 *    in the data store, or 1 if the file is missing from the data
 *    store.
 *
 *    Return SK_ITERATOR_OK when a file exists, or
 *    SK_ITERATOR_NO_MORE_ENTRIES when the iterator has visited all
 *    files.
 */
int
sksiteRepoIteratorNextPath(
    sksite_repo_iter_t *iter,
    char               *path,
    size_t              path_len,
    int                *is_missing);

/**
 *    Create a new stream holding the next file in the data store at
 *    the location specified by 'stream'.  If the file exists, the
 *    stream will be opened at the header of the file will be read.
 *    If 'is_missing' is not-NULL, it will be set to 0 if the file
 *    exists in the data store, or 1 if the file is missing from the
 *    data store.
 *
 *    If a file exists in the data store but there is an error opening
 *    the file, the stream is not returned by the iterator.  If 'err_fn'
 *    is not-NULL, a message will be printed using that function.
 *
 *    Return SK_ITERATOR_OK when a file exists, or
 *    SK_ITERATOR_NO_MORE_ENTRIES when the iterator has visited all
 *    files.
 */
int
sksiteRepoIteratorNextStream(
    sksite_repo_iter_t     *iter,
    skstream_t            **stream,
    int                    *is_missing,
    sk_msg_fn_t             err_fn);

/**
 *    Append all remaining file attributes to the 'attr_vec' vector.
 *    'attr_vec' should be a vector where the element size is
 *    sizeof(sksite_fileattr_t).  Return 0 on success, or -1 on
 *    failure.
 *
 *    This function does not provide any mechanism for the caller to
 *    determine whether an entry in the 'attr_vec' represents a
 *    missing file, when 'iter' is iterating over missing files.
 */
int
sksiteRepoIteratorRemainingFileattrs(
    sksite_repo_iter_t *iter,
    sk_vector_t        *fileattr_vec);

/**
 *    Reset the state of the iterator 'iter' so that all files may be
 *    iterated over again.
 */
void
sksiteRepoIteratorReset(
    sksite_repo_iter_t *iter);


/*
 *    The following have been renamed and moved to silk_files.h.
 */

int
sksiteCompmethodCheck(
    sk_compmethod_t     comp_method)
    SK_GCC_DEPRECATED;

sk_compmethod_t
sksiteCompmethodGetBest(
    void)
    SK_GCC_DEPRECATED;

sk_compmethod_t
sksiteCompmethodGetDefault(
    void)
    SK_GCC_DEPRECATED;

int
sksiteCompmethodGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_compmethod_t     comp_method)
    SK_GCC_DEPRECATED;

int
sksiteCompmethodSetDefault(
    sk_compmethod_t     compression_method)
    SK_GCC_DEPRECATED;

int
sksiteCompmethodOptionsRegister(
    sk_compmethod_t    *compression_method)
    SK_GCC_DEPRECATED;

void
sksiteCompmethodOptionsUsage(
    FILE               *fh)
    SK_GCC_DEPRECATED;

int
sksiteFileformatGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_file_format_t    format_id)
    SK_GCC_DEPRECATED;

int
sksiteFileformatIsValid(
    sk_file_format_t    format_id)
    SK_GCC_DEPRECATED;

sk_file_format_t
sksiteFileformatFromName(
    const char         *name)
    SK_GCC_DEPRECATED;



/** Iterator Definitions **********************************************/

/*
 *    Iterators should be created on the stack.
 *
 *    The internal structure of the iterator is visible here so they
 *    can be created on the stack.  However, the caller should treat
 *    the internals as opaque.
 */

/* Above: typedef struct sk_sensor_iter_st sk_sensor_iter_t; */
struct sk_sensor_iter_st {
    /** vector of candidates */
    sk_vector_t        *si_vector;
    /** position in the vector */
    int                 si_index;
    /** 1 if vector contains pointers, 0 if it contains IDs */
    int                 si_contains_pointers;
};

/* Above: typedef struct sk_class_iter_st sk_class_iter_t; */
struct sk_class_iter_st {
    /** vector of candidates */
    sk_vector_t        *ci_vector;
    /** position in the vector */
    int                 ci_index;
    /** 1 if vector contains pointers, 0 if it contains IDs */
    int                 ci_contains_pointers;
};

/* Above: typedef struct sk_sensorgroup_iter_st sk_sensorgroup_iter_t; */
struct sk_sensorgroup_iter_st {
    /** vector of candidates */
    sk_vector_t        *gi_vector;
    /** position in the vector */
    int                 gi_index;
    /** 1 if vector contains pointers, 0 if it contains IDs */
    int                 gi_contains_pointers;
};

/* Above: typedef struct sk_flowtype_iter_st sk_flowtype_iter_t; */
struct sk_flowtype_iter_st {
    /** vector of candidates */
    sk_vector_t        *fi_vector;
    /** position in the vector */
    int                 fi_index;
    /** 1 if vector contains pointers, 0 if it contains IDs */
    int                 fi_contains_pointers;
};


#ifdef __cplusplus
}
#endif
#endif /* _SKSITE_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
