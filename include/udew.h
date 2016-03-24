/*
 * Copyright 2016 Blender Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

#ifndef __UDEW_H__
#define __UDEW_H__

#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * udev - library context
 *
 * reads the udev config and system environment
 * allows custom logging
 */
struct udev;
typedef struct udev *tudev_ref(struct udev *udev);
typedef struct udev *tudev_unref(struct udev *udev);
typedef struct udev *tudev_new(void);
typedef void tudev_set_log_fn(struct udev *udev,
                            void (*log_fn)(struct udev *udev,
                                           int priority, const char *file, int line, const char *fn,
                                           const char *format, va_list args));
typedef int tudev_get_log_priority(struct udev *udev);
typedef void tudev_set_log_priority(struct udev *udev, int priority);
typedef void *tudev_get_userdata(struct udev *udev);
typedef void tudev_set_userdata(struct udev *udev, void *userdata);

/*
 * udev_list
 *
 * access to libudev generated lists
 */
struct udev_list_entry;
typedef struct udev_list_entry *tudev_list_entry_get_next(struct udev_list_entry *list_entry);
typedef struct udev_list_entry *tudev_list_entry_get_by_name(struct udev_list_entry *list_entry, const char *name);
typedef const char *tudev_list_entry_get_name(struct udev_list_entry *list_entry);
typedef const char *tudev_list_entry_get_value(struct udev_list_entry *list_entry);
/**
 * udev_list_entry_foreach:
 * @list_entry: entry to store the current position
 * @first_entry: first entry to start with
 *
 * Helper to iterate over all entries of a list.
 */
#define udev_list_entry_foreach(list_entry, first_entry) \
        for (list_entry = first_entry; \
             list_entry != NULL; \
             list_entry = udev_list_entry_get_next(list_entry))

/*
 * udev_device
 *
 * access to sysfs/kernel devices
 */
struct udev_device;
typedef struct udev_device *tudev_device_ref(struct udev_device *udev_device);
typedef struct udev_device *tudev_device_unref(struct udev_device *udev_device);
typedef struct udev *tudev_device_get_udev(struct udev_device *udev_device);
typedef struct udev_device *tudev_device_new_from_syspath(struct udev *udev, const char *syspath);
typedef struct udev_device *tudev_device_new_from_devnum(struct udev *udev, char type, dev_t devnum);
typedef struct udev_device *tudev_device_new_from_subsystem_sysname(struct udev *udev, const char *subsystem, const char *sysname);
typedef struct udev_device *tudev_device_new_from_device_id(struct udev *udev, const char *id);
typedef struct udev_device *tudev_device_new_from_environment(struct udev *udev);
/* udev_device_get_parent_*() does not take a reference on the returned device, it is automatically unref'd with the parent */
typedef struct udev_device *tudev_device_get_parent(struct udev_device *udev_device);
typedef struct udev_device *tudev_device_get_parent_with_subsystem_devtype(struct udev_device *udev_device,
                                                                  const char *subsystem, const char *devtype);
/* retrieve device properties */
typedef const char *tudev_device_get_devpath(struct udev_device *udev_device);
typedef const char *tudev_device_get_subsystem(struct udev_device *udev_device);
typedef const char *tudev_device_get_devtype(struct udev_device *udev_device);
typedef const char *tudev_device_get_syspath(struct udev_device *udev_device);
typedef const char *tudev_device_get_sysname(struct udev_device *udev_device);
typedef const char *tudev_device_get_sysnum(struct udev_device *udev_device);
typedef const char *tudev_device_get_devnode(struct udev_device *udev_device);
typedef int tudev_device_get_is_initialized(struct udev_device *udev_device);
typedef struct udev_list_entry *tudev_device_get_devlinks_list_entry(struct udev_device *udev_device);
typedef struct udev_list_entry *tudev_device_get_properties_list_entry(struct udev_device *udev_device);
typedef struct udev_list_entry *tudev_device_get_tags_list_entry(struct udev_device *udev_device);
typedef struct udev_list_entry *tudev_device_get_sysattr_list_entry(struct udev_device *udev_device);
typedef const char *tudev_device_get_property_value(struct udev_device *udev_device, const char *key);
typedef const char *tudev_device_get_driver(struct udev_device *udev_device);
typedef dev_t tudev_device_get_devnum(struct udev_device *udev_device);
typedef const char *tudev_device_get_action(struct udev_device *udev_device);
typedef unsigned long long int tudev_device_get_seqnum(struct udev_device *udev_device);
typedef unsigned long long int tudev_device_get_usec_since_initialized(struct udev_device *udev_device);
typedef const char *tudev_device_get_sysattr_value(struct udev_device *udev_device, const char *sysattr);
typedef int tudev_device_set_sysattr_value(struct udev_device *udev_device, const char *sysattr, char *value);
typedef int tudev_device_has_tag(struct udev_device *udev_device, const char *tag);

/*
 * udev_monitor
 *
 * access to kernel uevents and udev events
 */
struct udev_monitor;
typedef struct udev_monitor *tudev_monitor_ref(struct udev_monitor *udev_monitor);
typedef struct udev_monitor *tudev_monitor_unref(struct udev_monitor *udev_monitor);
typedef struct udev *tudev_monitor_get_udev(struct udev_monitor *udev_monitor);
/* kernel and udev generated events over netlink */
typedef struct udev_monitor *tudev_monitor_new_from_netlink(struct udev *udev, const char *name);
/* bind socket */
typedef int tudev_monitor_enable_receiving(struct udev_monitor *udev_monitor);
typedef int tudev_monitor_set_receive_buffer_size(struct udev_monitor *udev_monitor, int size);
typedef int tudev_monitor_get_fd(struct udev_monitor *udev_monitor);
typedef struct udev_device *tudev_monitor_receive_device(struct udev_monitor *udev_monitor);
/* in-kernel socket filters to select messages that get delivered to a listener */
typedef int tudev_monitor_filter_add_match_subsystem_devtype(struct udev_monitor *udev_monitor,
                                                    const char *subsystem, const char *devtype);
typedef int tudev_monitor_filter_add_match_tag(struct udev_monitor *udev_monitor, const char *tag);
typedef int tudev_monitor_filter_update(struct udev_monitor *udev_monitor);
typedef int tudev_monitor_filter_remove(struct udev_monitor *udev_monitor);

/*
 * udev_enumerate
 *
 * search sysfs for specific devices and provide a sorted list
 */
struct udev_enumerate;
typedef struct udev_enumerate *tudev_enumerate_ref(struct udev_enumerate *udev_enumerate);
typedef struct udev_enumerate *tudev_enumerate_unref(struct udev_enumerate *udev_enumerate);
typedef struct udev *tudev_enumerate_get_udev(struct udev_enumerate *udev_enumerate);
typedef struct udev_enumerate *tudev_enumerate_new(struct udev *udev);
/* device properties filter */
typedef int tudev_enumerate_add_match_subsystem(struct udev_enumerate *udev_enumerate, const char *subsystem);
typedef int tudev_enumerate_add_nomatch_subsystem(struct udev_enumerate *udev_enumerate, const char *subsystem);
typedef int tudev_enumerate_add_match_sysattr(struct udev_enumerate *udev_enumerate, const char *sysattr, const char *value);
typedef int tudev_enumerate_add_nomatch_sysattr(struct udev_enumerate *udev_enumerate, const char *sysattr, const char *value);
typedef int tudev_enumerate_add_match_property(struct udev_enumerate *udev_enumerate, const char *property, const char *value);
typedef int tudev_enumerate_add_match_sysname(struct udev_enumerate *udev_enumerate, const char *sysname);
typedef int tudev_enumerate_add_match_tag(struct udev_enumerate *udev_enumerate, const char *tag);
typedef int tudev_enumerate_add_match_parent(struct udev_enumerate *udev_enumerate, struct udev_device *parent);
typedef int tudev_enumerate_add_match_is_initialized(struct udev_enumerate *udev_enumerate);
typedef int tudev_enumerate_add_syspath(struct udev_enumerate *udev_enumerate, const char *syspath);
/* run enumeration with active filters */
typedef int tudev_enumerate_scan_devices(struct udev_enumerate *udev_enumerate);
typedef int tudev_enumerate_scan_subsystems(struct udev_enumerate *udev_enumerate);
/* return device list */
typedef struct udev_list_entry *tudev_enumerate_get_list_entry(struct udev_enumerate *udev_enumerate);

/*
 * udev_queue
 *
 * access to the currently running udev events
 */
struct udev_queue;
typedef struct udev_queue *tudev_queue_ref(struct udev_queue *udev_queue);
typedef struct udev_queue *tudev_queue_unref(struct udev_queue *udev_queue);
typedef struct udev *tudev_queue_get_udev(struct udev_queue *udev_queue);
typedef struct udev_queue *tudev_queue_new(struct udev *udev);
typedef unsigned long long int tudev_queue_get_kernel_seqnum(struct udev_queue *udev_queue);
typedef unsigned long long int tudev_queue_get_udev_seqnum(struct udev_queue *udev_queue);
typedef int tudev_queue_get_udev_is_active(struct udev_queue *udev_queue);
typedef int tudev_queue_get_queue_is_empty(struct udev_queue *udev_queue);
typedef int tudev_queue_get_seqnum_is_finished(struct udev_queue *udev_queue, unsigned long long int seqnum);
typedef int tudev_queue_get_seqnum_sequence_is_finished(struct udev_queue *udev_queue,
                                               unsigned long long int start, unsigned long long int end);
typedef int tudev_queue_get_fd(struct udev_queue *udev_queue);
typedef int tudev_queue_flush(struct udev_queue *udev_queue);
typedef struct udev_list_entry *tudev_queue_get_queued_list_entry(struct udev_queue *udev_queue);

/*
 *  udev_hwdb
 *
 *  access to the static hardware properties database
 */
struct udev_hwdb;
typedef struct udev_hwdb *tudev_hwdb_new(struct udev *udev);
typedef struct udev_hwdb *tudev_hwdb_ref(struct udev_hwdb *hwdb);
typedef struct udev_hwdb *tudev_hwdb_unref(struct udev_hwdb *hwdb);
typedef struct udev_list_entry *tudev_hwdb_get_properties_list_entry(struct udev_hwdb *hwdb, const char *modalias, unsigned int flags);

/*
 * udev_util
 *
 * udev specific utilities
 */
typedef int tudev_util_encode_string(const char *str, char *str_enc, size_t len);


extern tudev_ref *udev_ref;
extern tudev_unref *udev_unref;
extern tudev_new *udev_new;
extern tudev_set_log_fn *udev_set_log_fn;
extern tudev_get_log_priority *udev_get_log_priority;
extern tudev_set_log_priority *udev_set_log_priority;
extern tudev_get_userdata *udev_get_userdata;
extern tudev_set_userdata *udev_set_userdata;
extern tudev_list_entry_get_next *udev_list_entry_get_next;
extern tudev_list_entry_get_by_name *udev_list_entry_get_by_name;
extern tudev_list_entry_get_name *udev_list_entry_get_name;
extern tudev_list_entry_get_value *udev_list_entry_get_value;
extern tudev_device_ref *udev_device_ref;
extern tudev_device_unref *udev_device_unref;
extern tudev_device_get_udev *udev_device_get_udev;
extern tudev_device_new_from_syspath *udev_device_new_from_syspath;
extern tudev_device_new_from_devnum *udev_device_new_from_devnum;
extern tudev_device_new_from_subsystem_sysname *udev_device_new_from_subsystem_sysname;
extern tudev_device_new_from_device_id *udev_device_new_from_device_id;
extern tudev_device_new_from_environment *udev_device_new_from_environment;
extern tudev_device_get_parent *udev_device_get_parent;
extern tudev_device_get_parent_with_subsystem_devtype *udev_device_get_parent_with_subsystem_devtype;
extern tudev_device_get_devpath *udev_device_get_devpath;
extern tudev_device_get_subsystem *udev_device_get_subsystem;
extern tudev_device_get_devtype *udev_device_get_devtype;
extern tudev_device_get_syspath *udev_device_get_syspath;
extern tudev_device_get_sysname *udev_device_get_sysname;
extern tudev_device_get_sysnum *udev_device_get_sysnum;
extern tudev_device_get_devnode *udev_device_get_devnode;
extern tudev_device_get_is_initialized *udev_device_get_is_initialized;
extern tudev_device_get_devlinks_list_entry *udev_device_get_devlinks_list_entry;
extern tudev_device_get_properties_list_entry *udev_device_get_properties_list_entry;
extern tudev_device_get_tags_list_entry *udev_device_get_tags_list_entry;
extern tudev_device_get_sysattr_list_entry *udev_device_get_sysattr_list_entry;
extern tudev_device_get_property_value *udev_device_get_property_value;
extern tudev_device_get_driver *udev_device_get_driver;
extern tudev_device_get_devnum *udev_device_get_devnum;
extern tudev_device_get_action *udev_device_get_action;
extern tudev_device_get_seqnum *udev_device_get_seqnum;
extern tudev_device_get_usec_since_initialized *udev_device_get_usec_since_initialized;
extern tudev_device_get_sysattr_value *udev_device_get_sysattr_value;
extern tudev_device_set_sysattr_value *udev_device_set_sysattr_value;
extern tudev_device_has_tag *udev_device_has_tag;
extern tudev_monitor_ref *udev_monitor_ref;
extern tudev_monitor_unref *udev_monitor_unref;
extern tudev_monitor_get_udev *udev_monitor_get_udev;
extern tudev_monitor_new_from_netlink *udev_monitor_new_from_netlink;
extern tudev_monitor_enable_receiving *udev_monitor_enable_receiving;
extern tudev_monitor_set_receive_buffer_size *udev_monitor_set_receive_buffer_size;
extern tudev_monitor_get_fd *udev_monitor_get_fd;
extern tudev_monitor_receive_device *udev_monitor_receive_device;
extern tudev_monitor_filter_add_match_subsystem_devtype *udev_monitor_filter_add_match_subsystem_devtype;
extern tudev_monitor_filter_add_match_tag *udev_monitor_filter_add_match_tag;
extern tudev_monitor_filter_update *udev_monitor_filter_update;
extern tudev_monitor_filter_remove *udev_monitor_filter_remove;
extern tudev_enumerate_ref *udev_enumerate_ref;
extern tudev_enumerate_unref *udev_enumerate_unref;
extern tudev_enumerate_get_udev *udev_enumerate_get_udev;
extern tudev_enumerate_new *udev_enumerate_new;
extern tudev_enumerate_add_match_subsystem *udev_enumerate_add_match_subsystem;
extern tudev_enumerate_add_nomatch_subsystem *udev_enumerate_add_nomatch_subsystem;
extern tudev_enumerate_add_match_sysattr *udev_enumerate_add_match_sysattr;
extern tudev_enumerate_add_nomatch_sysattr *udev_enumerate_add_nomatch_sysattr;
extern tudev_enumerate_add_match_property *udev_enumerate_add_match_property;
extern tudev_enumerate_add_match_sysname *udev_enumerate_add_match_sysname;
extern tudev_enumerate_add_match_tag *udev_enumerate_add_match_tag;
extern tudev_enumerate_add_match_parent *udev_enumerate_add_match_parent;
extern tudev_enumerate_add_match_is_initialized *udev_enumerate_add_match_is_initialized;
extern tudev_enumerate_add_syspath *udev_enumerate_add_syspath;
extern tudev_enumerate_scan_devices *udev_enumerate_scan_devices;
extern tudev_enumerate_scan_subsystems *udev_enumerate_scan_subsystems;
extern tudev_enumerate_get_list_entry *udev_enumerate_get_list_entry;
extern tudev_queue_ref *udev_queue_ref;
extern tudev_queue_unref *udev_queue_unref;
extern tudev_queue_get_udev *udev_queue_get_udev;
extern tudev_queue_new *udev_queue_new;
extern tudev_queue_get_kernel_seqnum *udev_queue_get_kernel_seqnum;
extern tudev_queue_get_udev_seqnum *udev_queue_get_udev_seqnum;
extern tudev_queue_get_udev_is_active *udev_queue_get_udev_is_active;
extern tudev_queue_get_queue_is_empty *udev_queue_get_queue_is_empty;
extern tudev_queue_get_seqnum_is_finished *udev_queue_get_seqnum_is_finished;
extern tudev_queue_get_seqnum_sequence_is_finished *udev_queue_get_seqnum_sequence_is_finished;
extern tudev_queue_get_fd *udev_queue_get_fd;
extern tudev_queue_flush *udev_queue_flush;
extern tudev_queue_get_queued_list_entry *udev_queue_get_queued_list_entry;
extern tudev_hwdb_new *udev_hwdb_new;
extern tudev_hwdb_ref *udev_hwdb_ref;
extern tudev_hwdb_unref *udev_hwdb_unref;
extern tudev_hwdb_get_properties_list_entry *udev_hwdb_get_properties_list_entry;
extern tudev_util_encode_string *udev_util_encode_string;

enum {
  UDEW_SUCCESS = 0,
  UDEW_ERROR_OPEN_FAILED = -1,
  UDEW_ERROR_ATEXIT_FAILED = -2,
};

int udewInit(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
