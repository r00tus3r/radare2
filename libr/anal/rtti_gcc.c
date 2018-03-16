/* radare - LGPL - Copyright 2009-2018 - pancake, maijin, r00tus3r */

#include <r_anal.h>
#include "r_anal.h"

typedef struct type_info_t {
  ut32 vtable_addr;
  ut32 name_addr;
} type_info;

typedef struct class_type_info_t : public type_info_t {
} class_type_info;

typedef struct base_class_type_info_t {
  ut32 base_class_addr;
  ut32 offset_flags;
  enum offset_flags_masks {
    base_is_virtual = 0x1,
    base_is_public = 0x2
  };
} base_class_type_info;

typedef struct si_class_type_info_t : public class_type_info_t {
  ut32 base_class_addr;
} si_class_type_info;

typedef struct vmi_class_type_info_t : public class_type_info_t {
  int vmi_flags;
  int vmi_base_count;
  base_class_type_info_t vmi_bases[1];
  enum vmi_flags_masks {
    non_diamond_repeat_mask = 0x1,
    diamond_shaped_mask = 0x2,
    non_public_base_mask = 0x4,
    public_base_mask = 0x8
  };
} vmi_class_type_info;

static void rtti_gcc_print_complete_object_locator_recurse(RVTableContext *context, ut64 atAddress) {
  eprintf ("Work in Progress. RTTI not yet supported for Itanium. \n");
}

R_API void r_anal_rtti_gcc_print_at_vtable(RVTableContext *context, ut64 addr, int mode) {
  rtti_gcc_print_complete_object_locator_recurse (context, addr);
}
