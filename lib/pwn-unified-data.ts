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
