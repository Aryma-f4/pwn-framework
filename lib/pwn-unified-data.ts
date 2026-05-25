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
// Maps pwn-data technique IDs to their detailed knowledge base entries
export const KB_MAPPING: Record<string, TechniqueDetails | undefined> = {
  // ─── STACK-BASED TECHNIQUES ───
  'buffer_overflow': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'stack_pivot': PWN_KNOWLEDGE_BASE['stack_pivot'],
  'rop_chain': PWN_KNOWLEDGE_BASE['rop_chain_detailed'],
  'rop_exec': PWN_KNOWLEDGE_BASE['rop_chain_detailed'],
  'ret2csu': PWN_KNOWLEDGE_BASE['ret2csu'],
  'ret2dlresolve': PWN_KNOWLEDGE_BASE['ret2dlresolve'],
  'srop': PWN_KNOWLEDGE_BASE['srop'],
  'brop': PWN_KNOWLEDGE_BASE['brop_exploit'],
  'jop': PWN_KNOWLEDGE_BASE['brop_exploit'],
  'ret2vdso': PWN_KNOWLEDGE_BASE['brop_exploit'],
  'stack_clash': PWN_KNOWLEDGE_BASE['stack_pivot'],
  'signal_handler_exploit': PWN_KNOWLEDGE_BASE['signal_handler_exploit_kb'],

  // ─── FORMAT STRING TECHNIQUES ───
  'format_string': PWN_KNOWLEDGE_BASE['format_string_detailed'],
  'format_leak': PWN_KNOWLEDGE_BASE['format_string_detailed'],
  'format_write': PWN_KNOWLEDGE_BASE['format_string_detailed'],
  'got_overwrite': PWN_KNOWLEDGE_BASE['got_overwrite'],
  'canary_leak': PWN_KNOWLEDGE_BASE['canary_leak'],
  'leak_libc': PWN_KNOWLEDGE_BASE['format_string_detailed'],
  'leak_stack': PWN_KNOWLEDGE_BASE['format_string_detailed'],
  'stack_chk_fail_hijack': PWN_KNOWLEDGE_BASE['format_string_detailed'],
  'blind_format': PWN_KNOWLEDGE_BASE['format_string_detailed'],

  // ─── HEAP-BASED TECHNIQUES ───
  'heap_exploit': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'use_after_free': PWN_KNOWLEDGE_BASE['use_after_free_detailed'],
  'double_free': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'vtable_hijack': PWN_KNOWLEDGE_BASE['vtable_hijack_detailed'],
  'heap_control': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'heap_spray': PWN_KNOWLEDGE_BASE['heap_spray_detailed'],
  'house_of_force': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'house_of_spirit': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'house_of_einherjar': PWN_KNOWLEDGE_BASE['off_by_one_exploit'],
  'house_of_lore': PWN_KNOWLEDGE_BASE['house_of_lore'],
  'house_of_botcake': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'house_of_rabbit': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'house_of_roman': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'tcache_stashing': PWN_KNOWLEDGE_BASE['tcache_stashing_unlink_detailed'],
  'unsorted_bin_attack': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'large_bin_attack': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'first_fit': PWN_KNOWLEDGE_BASE['first_fit'],
  'poison_null_byte': PWN_KNOWLEDGE_BASE['poison_null_byte'],
  'house_of_husk': PWN_KNOWLEDGE_BASE['house_of_husk'],
  'house_of_corrosion': PWN_KNOWLEDGE_BASE['house_of_corrosion'],
  'house_of_apple': PWN_KNOWLEDGE_BASE['house_of_apple'],
  'house_of_cat': PWN_KNOWLEDGE_BASE['house_of_cat'],
  'overlapping_chunks': PWN_KNOWLEDGE_BASE['overlapping_chunks_detailed'],

  // ─── FSOP ───
  'fsop_exploit': PWN_KNOWLEDGE_BASE['fsop_exploit'],
  'house_of_orange': PWN_KNOWLEDGE_BASE['fsop_exploit'],

  // ─── MITIGATION BYPASS ───
  'aslr_prot': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'info_leak_bypass': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'partial_overwrite': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'nx_prot': PWN_KNOWLEDGE_BASE['stack_buffer_overflow'],
  'rop_bypass': PWN_KNOWLEDGE_BASE['rop_chain_detailed'],
  'canary_prot': PWN_KNOWLEDGE_BASE['canary_leak'],
  'canary_leak': PWN_KNOWLEDGE_BASE['canary_leak'],
  'canary_bruteforce': PWN_KNOWLEDGE_BASE['canary_bruteforce'],
  'relro_prot': PWN_KNOWLEDGE_BASE['relational_bypass_detailed'],
  'relro_bypass': PWN_KNOWLEDGE_BASE['relational_bypass_detailed'],

  // ─── SANDBOX / KERNEL ───
  'sandbox_escape': PWN_KNOWLEDGE_BASE['sandbox_escape'],
  'privilege_escalation': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'kernel_rce': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'msg_msg_corruption': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'userfaultfd_exploit': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'ret2usr': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'capability_abuse': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'modprobe_path': PWN_KNOWLEDGE_BASE['kernel_privilege_escalation'],
  'dirty_cow': PWN_KNOWLEDGE_BASE['sandbox_escape'],
  'ipc_exploit': PWN_KNOWLEDGE_BASE['sandbox_escape'],
  'mojo_exploit': PWN_KNOWLEDGE_BASE['sandbox_escape'],
  'ebpf_exploit': PWN_KNOWLEDGE_BASE['ebpf_exploit_detailed'],

  // ─── INTEGER TECHNIQUES ───
  'integer_exploits': PWN_KNOWLEDGE_BASE['integer_exploit_techniques'],
  'integer_overflow': PWN_KNOWLEDGE_BASE['integer_exploit_techniques'],
  'integer_underflow': PWN_KNOWLEDGE_BASE['integer_exploit_techniques'],
  'sign_extension': PWN_KNOWLEDGE_BASE['integer_exploit_techniques'],
  'off_by_one': PWN_KNOWLEDGE_BASE['off_by_one_exploit'],

  // ─── HOW2HEAP TECHNIQUES ───
  'unsafe_unlink': PWN_KNOWLEDGE_BASE['unsafe_unlink'],
  'overlapping_chunks_h2h': PWN_KNOWLEDGE_BASE['overlapping_chunks'],
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
  'safe_linking_bypass': PWN_KNOWLEDGE_BASE['safe_linking_bypass'],
  'large_bin_attack_modern': PWN_KNOWLEDGE_BASE['large_bin_attack_modern'],
  'unsorted_bin_attack_classic': PWN_KNOWLEDGE_BASE['unsorted_bin_attack_classic'],
  'house_of_prime': PWN_KNOWLEDGE_BASE['house_of_prime'],
  'house_of_rust': PWN_KNOWLEDGE_BASE['house_of_rust'],
  'house_of_mind_original': PWN_KNOWLEDGE_BASE['house_of_mind_original'],

  // ─── HEAP ALIASES ───
  'fastbin_dup_into_stack': PWN_KNOWLEDGE_BASE['fastbin_reverse_into_tcache'],
  'poison_null': PWN_KNOWLEDGE_BASE['poison_null_byte'],
  'off_by_one_null': PWN_KNOWLEDGE_BASE['poison_null_byte'],
  'top_chunk_shrink': PWN_KNOWLEDGE_BASE['house_of_corrosion'],
  'first_fit_demo': PWN_KNOWLEDGE_BASE['first_fit'],
  'printf_func_hijack': PWN_KNOWLEDGE_BASE['house_of_husk'],
  'wide_data_vtable': PWN_KNOWLEDGE_BASE['house_of_cat'],
  'heap_overflow': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],
  'tcache_poison': PWN_KNOWLEDGE_BASE['heap_buffer_overflow'],

  // ─── SETUP TOOLS ───
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