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

#ifdef _MSC_VER
#  define snprintf _snprintf
#  define popen _popen
#  define pclose _pclose
#  define _CRT_SECURE_NO_WARNINGS
#endif

#include "udew.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  define VC_EXTRALEAN
#  include <windows.h>

/* Utility macros. */

typedef HMODULE DynamicLibrary;

#  define dynamic_library_open(path)         LoadLibrary(path)
#  define dynamic_library_close(lib)         FreeLibrary(lib)
#  define dynamic_library_find(lib, symbol)  GetProcAddress(lib, symbol)
#else
#  include <dlfcn.h>

typedef void* DynamicLibrary;

#  define dynamic_library_open(path)         dlopen(path, RTLD_NOW)
#  define dynamic_library_close(lib)         dlclose(lib)
#  define dynamic_library_find(lib, symbol)  dlsym(lib, symbol)
#endif

#define UDEV_LIBRARY_FIND_CHECKED(name)         name = (t##name *)dynamic_library_find(lib, #name);         assert(name);

#define UDEV_LIBRARY_FIND(name)         name = (t##name *)dynamic_library_find(lib, #name);

static DynamicLibrary lib;

tudev_ref *udev_ref;
tudev_unref *udev_unref;
tudev_new *udev_new;
tudev_set_log_fn *udev_set_log_fn;
tudev_get_log_priority *udev_get_log_priority;
tudev_set_log_priority *udev_set_log_priority;
tudev_get_userdata *udev_get_userdata;
tudev_set_userdata *udev_set_userdata;
tudev_list_entry_get_next *udev_list_entry_get_next;
tudev_list_entry_get_by_name *udev_list_entry_get_by_name;
tudev_list_entry_get_name *udev_list_entry_get_name;
tudev_list_entry_get_value *udev_list_entry_get_value;
tudev_device_ref *udev_device_ref;
tudev_device_unref *udev_device_unref;
tudev_device_get_udev *udev_device_get_udev;
tudev_device_new_from_syspath *udev_device_new_from_syspath;
tudev_device_new_from_devnum *udev_device_new_from_devnum;
tudev_device_new_from_subsystem_sysname *udev_device_new_from_subsystem_sysname;
tudev_device_new_from_device_id *udev_device_new_from_device_id;
tudev_device_new_from_environment *udev_device_new_from_environment;
tudev_device_get_parent *udev_device_get_parent;
tudev_device_get_parent_with_subsystem_devtype *udev_device_get_parent_with_subsystem_devtype;
tudev_device_get_devpath *udev_device_get_devpath;
tudev_device_get_subsystem *udev_device_get_subsystem;
tudev_device_get_devtype *udev_device_get_devtype;
tudev_device_get_syspath *udev_device_get_syspath;
tudev_device_get_sysname *udev_device_get_sysname;
tudev_device_get_sysnum *udev_device_get_sysnum;
tudev_device_get_devnode *udev_device_get_devnode;
tudev_device_get_is_initialized *udev_device_get_is_initialized;
tudev_device_get_devlinks_list_entry *udev_device_get_devlinks_list_entry;
tudev_device_get_properties_list_entry *udev_device_get_properties_list_entry;
tudev_device_get_tags_list_entry *udev_device_get_tags_list_entry;
tudev_device_get_sysattr_list_entry *udev_device_get_sysattr_list_entry;
tudev_device_get_property_value *udev_device_get_property_value;
tudev_device_get_driver *udev_device_get_driver;
tudev_device_get_devnum *udev_device_get_devnum;
tudev_device_get_action *udev_device_get_action;
tudev_device_get_seqnum *udev_device_get_seqnum;
tudev_device_get_usec_since_initialized *udev_device_get_usec_since_initialized;
tudev_device_get_sysattr_value *udev_device_get_sysattr_value;
tudev_device_set_sysattr_value *udev_device_set_sysattr_value;
tudev_device_has_tag *udev_device_has_tag;
tudev_monitor_ref *udev_monitor_ref;
tudev_monitor_unref *udev_monitor_unref;
tudev_monitor_get_udev *udev_monitor_get_udev;
tudev_monitor_new_from_netlink *udev_monitor_new_from_netlink;
tudev_monitor_enable_receiving *udev_monitor_enable_receiving;
tudev_monitor_set_receive_buffer_size *udev_monitor_set_receive_buffer_size;
tudev_monitor_get_fd *udev_monitor_get_fd;
tudev_monitor_receive_device *udev_monitor_receive_device;
tudev_monitor_filter_add_match_subsystem_devtype *udev_monitor_filter_add_match_subsystem_devtype;
tudev_monitor_filter_add_match_tag *udev_monitor_filter_add_match_tag;
tudev_monitor_filter_update *udev_monitor_filter_update;
tudev_monitor_filter_remove *udev_monitor_filter_remove;
tudev_enumerate_ref *udev_enumerate_ref;
tudev_enumerate_unref *udev_enumerate_unref;
tudev_enumerate_get_udev *udev_enumerate_get_udev;
tudev_enumerate_new *udev_enumerate_new;
tudev_enumerate_add_match_subsystem *udev_enumerate_add_match_subsystem;
tudev_enumerate_add_nomatch_subsystem *udev_enumerate_add_nomatch_subsystem;
tudev_enumerate_add_match_sysattr *udev_enumerate_add_match_sysattr;
tudev_enumerate_add_nomatch_sysattr *udev_enumerate_add_nomatch_sysattr;
tudev_enumerate_add_match_property *udev_enumerate_add_match_property;
tudev_enumerate_add_match_sysname *udev_enumerate_add_match_sysname;
tudev_enumerate_add_match_tag *udev_enumerate_add_match_tag;
tudev_enumerate_add_match_parent *udev_enumerate_add_match_parent;
tudev_enumerate_add_match_is_initialized *udev_enumerate_add_match_is_initialized;
tudev_enumerate_add_syspath *udev_enumerate_add_syspath;
tudev_enumerate_scan_devices *udev_enumerate_scan_devices;
tudev_enumerate_scan_subsystems *udev_enumerate_scan_subsystems;
tudev_enumerate_get_list_entry *udev_enumerate_get_list_entry;
tudev_queue_ref *udev_queue_ref;
tudev_queue_unref *udev_queue_unref;
tudev_queue_get_udev *udev_queue_get_udev;
tudev_queue_new *udev_queue_new;
tudev_queue_get_kernel_seqnum *udev_queue_get_kernel_seqnum;
tudev_queue_get_udev_seqnum *udev_queue_get_udev_seqnum;
tudev_queue_get_udev_is_active *udev_queue_get_udev_is_active;
tudev_queue_get_queue_is_empty *udev_queue_get_queue_is_empty;
tudev_queue_get_seqnum_is_finished *udev_queue_get_seqnum_is_finished;
tudev_queue_get_seqnum_sequence_is_finished *udev_queue_get_seqnum_sequence_is_finished;
tudev_queue_get_fd *udev_queue_get_fd;
tudev_queue_flush *udev_queue_flush;
tudev_queue_get_queued_list_entry *udev_queue_get_queued_list_entry;
tudev_hwdb_new *udev_hwdb_new;
tudev_hwdb_ref *udev_hwdb_ref;
tudev_hwdb_unref *udev_hwdb_unref;
tudev_hwdb_get_properties_list_entry *udev_hwdb_get_properties_list_entry;
tudev_util_encode_string *udev_util_encode_string;

static DynamicLibrary dynamic_library_open_find(const char **paths) {
  int i = 0;
  while (paths[i] != NULL) {
      DynamicLibrary lib = dynamic_library_open(paths[i]);
      if (lib != NULL) {
        return lib;
      }
      ++i;
  }
  return NULL;
}

static void udewExit(void) {
  if(lib != NULL) {
    /*  Ignore errors. */
    dynamic_library_close(lib);
    lib = NULL;
  }
}

/* Implementation function. */
int udewInit(void) {
  /* Library paths. */
#ifdef _WIN32
  /* Expected in c:/windows/system or similar, no path needed. */
  const char *paths[] = {"udev.dll", NULL};
#elif defined(__APPLE__)
  /* Default installation path. */
  const char *paths[] = {"libudev.dylib", NULL};
#else
  const char *paths[] = {"libudev.so",
                         "libudev.so.0",
                         "libudev.so.1",
                         "libudev.so.2",
                         NULL};
#endif
  static int initialized = 0;
  static int result = 0;
  int error;

  if (initialized) {
    return result;
  }

  initialized = 1;

  error = atexit(udewExit);
  if (error) {
    result = UDEW_ERROR_ATEXIT_FAILED;
    return result;
  }

  /* Load library. */
  lib = dynamic_library_open_find(paths);

  if (lib == NULL) {
    result = UDEW_ERROR_OPEN_FAILED;
    return result;
  }

  UDEV_LIBRARY_FIND(udev_ref);
  UDEV_LIBRARY_FIND(udev_unref);
  UDEV_LIBRARY_FIND(udev_new);
  UDEV_LIBRARY_FIND(udev_set_log_fn);
  UDEV_LIBRARY_FIND(udev_get_log_priority);
  UDEV_LIBRARY_FIND(udev_set_log_priority);
  UDEV_LIBRARY_FIND(udev_get_userdata);
  UDEV_LIBRARY_FIND(udev_set_userdata);
  UDEV_LIBRARY_FIND(udev_list_entry_get_next);
  UDEV_LIBRARY_FIND(udev_list_entry_get_by_name);
  UDEV_LIBRARY_FIND(udev_list_entry_get_name);
  UDEV_LIBRARY_FIND(udev_list_entry_get_value);
  UDEV_LIBRARY_FIND(udev_device_ref);
  UDEV_LIBRARY_FIND(udev_device_unref);
  UDEV_LIBRARY_FIND(udev_device_get_udev);
  UDEV_LIBRARY_FIND(udev_device_new_from_syspath);
  UDEV_LIBRARY_FIND(udev_device_new_from_devnum);
  UDEV_LIBRARY_FIND(udev_device_new_from_subsystem_sysname);
  UDEV_LIBRARY_FIND(udev_device_new_from_device_id);
  UDEV_LIBRARY_FIND(udev_device_new_from_environment);
  UDEV_LIBRARY_FIND(udev_device_get_parent);
  UDEV_LIBRARY_FIND(udev_device_get_parent_with_subsystem_devtype);
  UDEV_LIBRARY_FIND(udev_device_get_devpath);
  UDEV_LIBRARY_FIND(udev_device_get_subsystem);
  UDEV_LIBRARY_FIND(udev_device_get_devtype);
  UDEV_LIBRARY_FIND(udev_device_get_syspath);
  UDEV_LIBRARY_FIND(udev_device_get_sysname);
  UDEV_LIBRARY_FIND(udev_device_get_sysnum);
  UDEV_LIBRARY_FIND(udev_device_get_devnode);
  UDEV_LIBRARY_FIND(udev_device_get_is_initialized);
  UDEV_LIBRARY_FIND(udev_device_get_devlinks_list_entry);
  UDEV_LIBRARY_FIND(udev_device_get_properties_list_entry);
  UDEV_LIBRARY_FIND(udev_device_get_tags_list_entry);
  UDEV_LIBRARY_FIND(udev_device_get_sysattr_list_entry);
  UDEV_LIBRARY_FIND(udev_device_get_property_value);
  UDEV_LIBRARY_FIND(udev_device_get_driver);
  UDEV_LIBRARY_FIND(udev_device_get_devnum);
  UDEV_LIBRARY_FIND(udev_device_get_action);
  UDEV_LIBRARY_FIND(udev_device_get_seqnum);
  UDEV_LIBRARY_FIND(udev_device_get_usec_since_initialized);
  UDEV_LIBRARY_FIND(udev_device_get_sysattr_value);
  UDEV_LIBRARY_FIND(udev_device_set_sysattr_value);
  UDEV_LIBRARY_FIND(udev_device_has_tag);
  UDEV_LIBRARY_FIND(udev_monitor_ref);
  UDEV_LIBRARY_FIND(udev_monitor_unref);
  UDEV_LIBRARY_FIND(udev_monitor_get_udev);
  UDEV_LIBRARY_FIND(udev_monitor_new_from_netlink);
  UDEV_LIBRARY_FIND(udev_monitor_enable_receiving);
  UDEV_LIBRARY_FIND(udev_monitor_set_receive_buffer_size);
  UDEV_LIBRARY_FIND(udev_monitor_get_fd);
  UDEV_LIBRARY_FIND(udev_monitor_receive_device);
  UDEV_LIBRARY_FIND(udev_monitor_filter_add_match_subsystem_devtype);
  UDEV_LIBRARY_FIND(udev_monitor_filter_add_match_tag);
  UDEV_LIBRARY_FIND(udev_monitor_filter_update);
  UDEV_LIBRARY_FIND(udev_monitor_filter_remove);
  UDEV_LIBRARY_FIND(udev_enumerate_ref);
  UDEV_LIBRARY_FIND(udev_enumerate_unref);
  UDEV_LIBRARY_FIND(udev_enumerate_get_udev);
  UDEV_LIBRARY_FIND(udev_enumerate_new);
  UDEV_LIBRARY_FIND(udev_enumerate_add_match_subsystem);
  UDEV_LIBRARY_FIND(udev_enumerate_add_nomatch_subsystem);
  UDEV_LIBRARY_FIND(udev_enumerate_add_match_sysattr);
  UDEV_LIBRARY_FIND(udev_enumerate_add_nomatch_sysattr);
  UDEV_LIBRARY_FIND(udev_enumerate_add_match_property);
  UDEV_LIBRARY_FIND(udev_enumerate_add_match_sysname);
  UDEV_LIBRARY_FIND(udev_enumerate_add_match_tag);
  UDEV_LIBRARY_FIND(udev_enumerate_add_match_parent);
  UDEV_LIBRARY_FIND(udev_enumerate_add_match_is_initialized);
  UDEV_LIBRARY_FIND(udev_enumerate_add_syspath);
  UDEV_LIBRARY_FIND(udev_enumerate_scan_devices);
  UDEV_LIBRARY_FIND(udev_enumerate_scan_subsystems);
  UDEV_LIBRARY_FIND(udev_enumerate_get_list_entry);
  UDEV_LIBRARY_FIND(udev_queue_ref);
  UDEV_LIBRARY_FIND(udev_queue_unref);
  UDEV_LIBRARY_FIND(udev_queue_get_udev);
  UDEV_LIBRARY_FIND(udev_queue_new);
  UDEV_LIBRARY_FIND(udev_queue_get_kernel_seqnum);
  UDEV_LIBRARY_FIND(udev_queue_get_udev_seqnum);
  UDEV_LIBRARY_FIND(udev_queue_get_udev_is_active);
  UDEV_LIBRARY_FIND(udev_queue_get_queue_is_empty);
  UDEV_LIBRARY_FIND(udev_queue_get_seqnum_is_finished);
  UDEV_LIBRARY_FIND(udev_queue_get_seqnum_sequence_is_finished);
  UDEV_LIBRARY_FIND(udev_queue_get_fd);
  UDEV_LIBRARY_FIND(udev_queue_flush);
  UDEV_LIBRARY_FIND(udev_queue_get_queued_list_entry);
  UDEV_LIBRARY_FIND(udev_hwdb_new);
  UDEV_LIBRARY_FIND(udev_hwdb_ref);
  UDEV_LIBRARY_FIND(udev_hwdb_unref);
  UDEV_LIBRARY_FIND(udev_hwdb_get_properties_list_entry);
  UDEV_LIBRARY_FIND(udev_util_encode_string);

  result = UDEW_SUCCESS;

  return result;
}
