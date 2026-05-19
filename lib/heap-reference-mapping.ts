// Map technique IDs to their corresponding heap exploitation information
import { HEAP_TECHNIQUES, HeapTechnique } from './heap-techniques';

export function getHeapReferenceForTechnique(techniqueId: string): HeapTechnique | undefined {
  const mappings: Record<string, string> = {
    'fastbin': 'fastbin-dup',
    'tcache': 'tcache-poisoning',
    'tcache-dup': 'tcache-dup',
    'house-of-spirit': 'house-of-spirit',
    'house-of-force': 'house-of-force',
    'house-of-lore': 'house-of-lore',
    'unsorted-bin': 'unsorted-bin-attack',
    'unsorted-bin-attack': 'unsorted-bin-attack',
    'house-of-einherjar': 'house-of-einherjar',
    'large-bin': 'large-bin-attack',
    'large-bin-attack': 'large-bin-attack',
    'house-of-botcake': 'house-of-botcake',
    'house-of-roman': 'house-of-roman',
    'house-of-rabbit': 'house-of-force',
    'buffer-overflow': 'fastbin-dup',
    'heap': 'tcache-poisoning',
    'exploit': 'house-of-force',
  };

  const mappedId = mappings[techniqueId.toLowerCase()] || techniqueId;
  return HEAP_TECHNIQUES[mappedId];
}

export function getAllHeapTechniques(): HeapTechnique[] {
  return Object.values(HEAP_TECHNIQUES);
}

export function getHeapTechniquesByCategory(category: string): HeapTechnique[] {
  return Object.values(HEAP_TECHNIQUES).filter(
    (tech) => tech.category === category
  );
}

export function getHeapTechniquesByDifficulty(difficulty: 'Easy' | 'Medium' | 'Hard' | 'Expert'): HeapTechnique[] {
  return Object.values(HEAP_TECHNIQUES).filter(
    (tech) => tech.difficulty === difficulty
  );
}

export function searchHeapTechniques(query: string): HeapTechnique[] {
  const lowercaseQuery = query.toLowerCase();
  return Object.values(HEAP_TECHNIQUES).filter(
    (tech) =>
      tech.name.toLowerCase().includes(lowercaseQuery) ||
      tech.description.toLowerCase().includes(lowercaseQuery) ||
      tech.vulnerability.toLowerCase().includes(lowercaseQuery)
  );
}
