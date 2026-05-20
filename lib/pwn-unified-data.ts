import { Technique } from './pwn-data';
import { PWN_KNOWLEDGE_BASE, TechniqueDetails } from './pwn-knowledge-base';

// This file enriches the original pwn-data with knowledge base information
export function enrichTechniqueWithKB(technique: Technique): Technique & Partial<TechniqueDetails> {
  // Try to find matching knowledge base entry
  const matchedKB = Object.values(PWN_KNOWLEDGE_BASE).find((kb) => {
    const techLower = technique.name.toLowerCase();
    const kbNameLower = kb.name.toLowerCase();
    // Match by exact name or by partial match
    return (
      techLower === kbNameLower ||
      techLower.includes(kbNameLower.split('(')[0].trim()) ||
      kbNameLower.includes(techLower.split('(')[0].trim())
    );
  });

  return {
    ...technique,
    ...(matchedKB ? matchedKB : {}),
  };
}

// Knowledge base mapping by technique ID
export const KB_MAPPING: Record<string, TechniqueDetails | undefined> = {
  'buffer_overflow': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'stack_pivot': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'rop_chain': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'rop_execution': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'ret2libc': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'ret2plt': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'ret2syscall': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'info_leak': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'memory_leak': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],

  'format_string': PWN_KNOWLEDGE_BASE['format_string_vulnerability'],
  'format_read': PWN_KNOWLEDGE_BASE['format_string_vulnerability'],
  'format_write': PWN_KNOWLEDGE_BASE['format_string_vulnerability'],
  'got_overwrite': PWN_KNOWLEDGE_BASE['format_string_vulnerability'],
  'canary_leak': PWN_KNOWLEDGE_BASE['format_string_vulnerability'],

  'heap_exploit': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'heap_overflow': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'double_free': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'use_after_free': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'tcache_poison': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'fastbin_dup': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'house_of_force': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'heap_spray': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],

  'sandbox_escape': PWN_KNOWLEDGE_BASE['sandbox_escape'],
  'seccomp_bypass': PWN_KNOWLEDGE_BASE['sandbox_escape'],
  'orw_chain': PWN_KNOWLEDGE_BASE['sandbox_escape'],
  'kernel_rce': PWN_KNOWLEDGE_BASE['sandbox_escape'],
  'dirty_cow': PWN_KNOWLEDGE_BASE['sandbox_escape'],
  'modprobe_path': PWN_KNOWLEDGE_BASE['sandbox_escape'],
  'ret2usr': PWN_KNOWLEDGE_BASE['sandbox_escape'],
  'capability_abuse': PWN_KNOWLEDGE_BASE['sandbox_escape'],

  'ret2csu': PWN_KNOWLEDGE_BASE['ret2csu'],
  'ret2dlresolve': PWN_KNOWLEDGE_BASE['ret2dlresolve'],
  'srop': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'stack_clash': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'blind_format': PWN_KNOWLEDGE_BASE['format_string_vulnerability'],
  
  'house_of_botcake': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'house_of_rabbit': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'house_of_roman': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'tcache_stashing': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  
  'fsop_exploit': PWN_KNOWLEDGE_BASE['fsop_exploit'],
  'house_of_apple': PWN_KNOWLEDGE_BASE['fsop_exploit'],
  'house_of_orange': PWN_KNOWLEDGE_BASE['fsop_exploit'],

  'srop': PWN_KNOWLEDGE_BASE['srop'],
  'stack_pivot': PWN_KNOWLEDGE_BASE['stack_pivot'],
  'brop': PWN_KNOWLEDGE_BASE['brop_exploit'],
  'jop': PWN_KNOWLEDGE_BASE['brop_exploit'],
  'ret2vdso': PWN_KNOWLEDGE_BASE['brop_exploit'],
  'rop_exec': PWN_KNOWLEDGE_BASE['stack_pivot'],

  'integer_exploits': PWN_KNOWLEDGE_BASE['integer_exploit_techniques'],
  'integer_overflow': PWN_KNOWLEDGE_BASE['integer_exploit_techniques'],
  'integer_underflow': PWN_KNOWLEDGE_BASE['integer_exploit_techniques'],
  'sign_extension': PWN_KNOWLEDGE_BASE['integer_exploit_techniques'],

  'off_by_one': PWN_KNOWLEDGE_BASE['off_by_one_exploit'],

  'use_after_free': PWN_KNOWLEDGE_BASE['use_after_free_detailed'],
  'vtable_hijack': PWN_KNOWLEDGE_BASE['use_after_free_detailed'],

  'tcache_stashing': PWN_KNOWLEDGE_BASE['tcache_stashing_unlink_detailed'],

  'ebpf_exploit': PWN_KNOWLEDGE_BASE['ebpf_exploit_detailed'],

  'privilege_escalation': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'kernel_rce': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'msg_msg_corruption': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'userfaultfd_exploit': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'ret2usr': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'capability_abuse': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'modprobe_path': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'dirty_cow': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],

  'house_of_force': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'house_of_spirit': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'house_of_einherjar': PWN_KNOWLEDGE_BASE['off_by_one_exploit'],
  'unsorted_bin_attack': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'large_bin_attack': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'heap_control': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],

  'ipc_exploit': PWN_KNOWLEDGE_BASE['sandbox_escape'],
  'mojo_exploit': PWN_KNOWLEDGE_BASE['sandbox_escape'],

  'stack_chk_fail_hijack': PWN_KNOWLEDGE_BASE['format_string_vulnerability'],
  'stack_clash': PWN_KNOWLEDGE_BASE['stack_pivot'],

  // how2heap new entries
  'unsafe_unlink': PWN_KNOWLEDGE_BASE['unsafe_unlink'],
  'overlapping_chunks': PWN_KNOWLEDGE_BASE['overlapping_chunks'],
  'unsorted_bin_into_stack': PWN_KNOWLEDGE_BASE['unsorted_bin_into_stack'],
  'house_of_water': PWN_KNOWLEDGE_BASE['house_of_water'],
  'house_of_tangerine': PWN_KNOWLEDGE_BASE['house_of_tangerine'],
  'tcache_house_of_spirit': PWN_KNOWLEDGE_BASE['tcache_house_of_spirit'],
  'fastbin_reverse_into_tcache': PWN_KNOWLEDGE_BASE['fastbin_reverse_into_tcache'],
  'house_of_mind_fastbin': PWN_KNOWLEDGE_BASE['house_of_mind_fastbin'],
  'house_of_storm': PWN_KNOWLEDGE_BASE['house_of_storm'],
  'house_of_gods': PWN_KNOWLEDGE_BASE['house_of_gods'],
  'decrypt_safe_linking': PWN_KNOWLEDGE_BASE['decrypt_safe_linking'],
  'tcache_metadata_poisoning': PWN_KNOWLEDGE_BASE['tcache_metadata_poisoning'],
  'house_of_io': PWN_KNOWLEDGE_BASE['house_of_io'],
  'tcache_relative_write': PWN_KNOWLEDGE_BASE['tcache_relative_write'],
  'tcache_metadata_hijacking': PWN_KNOWLEDGE_BASE['tcache_metadata_hijacking'],
  'fastbin_dup_consolidate': PWN_KNOWLEDGE_BASE['fastbin_dup_consolidate'],
  'mmap_overlapping_chunks': PWN_KNOWLEDGE_BASE['mmap_overlapping_chunks'],
  'sysmalloc_int_free': PWN_KNOWLEDGE_BASE['sysmalloc_int_free'],
  'safe_link_double_protect': PWN_KNOWLEDGE_BASE['safe_link_double_protect'],

  // how2heap additions - round 2
  'first_fit': PWN_KNOWLEDGE_BASE['first_fit'],
  'poison_null_byte': PWN_KNOWLEDGE_BASE['poison_null_byte'],
  'house_of_husk': PWN_KNOWLEDGE_BASE['house_of_husk'],
  'house_of_corrosion': PWN_KNOWLEDGE_BASE['house_of_corrosion'],
  'house_of_cat': PWN_KNOWLEDGE_BASE['house_of_cat'],

  // heap technique aliases
  'fastbin_dup_into_stack': PWN_KNOWLEDGE_BASE['fastbin_reverse_into_tcache'],
  'poison_null': PWN_KNOWLEDGE_BASE['poison_null_byte'],
  'off_by_one_null': PWN_KNOWLEDGE_BASE['poison_null_byte'],
  'top_chunk_shrink': PWN_KNOWLEDGE_BASE['house_of_corrosion'],
  'first_fit_demo': PWN_KNOWLEDGE_BASE['first_fit'],
  'printf_func_hijack': PWN_KNOWLEDGE_BASE['house_of_husk'],
  'wide_data_vtable': PWN_KNOWLEDGE_BASE['house_of_cat'],

  // setup tools
  'setup_gdb': PWN_KNOWLEDGE_BASE['setup_gdb'],
  'setup_pwntools': PWN_KNOWLEDGE_BASE['setup_pwntools'],
  'setup_ghidra': PWN_KNOWLEDGE_BASE['setup_ghidra'],
  'setup_ida': PWN_KNOWLEDGE_BASE['setup_ida'],
  'setup_checksec': PWN_KNOWLEDGE_BASE['setup_checksec'],
  'setup_ropper': PWN_KNOWLEDGE_BASE['setup_ropper'],
  'setup_libc_db': PWN_KNOWLEDGE_BASE['setup_libc_db'],
  'setup_seccomp_tools': PWN_KNOWLEDGE_BASE['setup_seccomp_tools'],
  'setup_patchelf': PWN_KNOWLEDGE_BASE['setup_patchelf'],
  'setup_qemu': PWN_KNOWLEDGE_BASE['setup_qemu'],
  'setup_tools_root': PWN_KNOWLEDGE_BASE['setup_gdb'],
};

export function getTechniqueKB(techniqueId: string): TechniqueDetails | undefined {
  return KB_MAPPING[techniqueId];
}

export function enrichedTechnique(technique: Technique): Technique & Partial<TechniqueDetails> {
  const kb = KB_MAPPING[technique.id];
  return {
    ...technique,
    ...(kb ? kb : {}),
  };
}
