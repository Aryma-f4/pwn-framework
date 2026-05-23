/**
 * Custom hook for tree navigation logic
 * Handles node selection, expansion/collapse, and tree state management
 */

import { useState, useCallback } from 'react';
import { Technique } from '@/lib/pwn-data';
import { logger } from '@/lib/logger';

export function useTreeNavigation() {
  const [selectedNode, setSelectedNode] = useState<Technique | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  const [collapsedNodes, setCollapsedNodes] = useState<Set<string>>(new Set());

  /**
   * Select a node
   */
  const selectNode = useCallback((node: Technique | null) => {
    setSelectedNode(node);
    if (node) {
      logger.debug(`Node selected: ${node.id}`);
    }
  }, []);

  /**
   * Toggle node expansion
   */
  const toggleNode = useCallback((nodeId: string) => {
    setExpandedNodes(prev => {
      const next = new Set(prev);
      if (next.has(nodeId)) {
        next.delete(nodeId);
        setCollapsedNodes(prev => new Set([...prev, nodeId]));
      } else {
        next.add(nodeId);
        setCollapsedNodes(prev => {
          const next = new Set(prev);
          next.delete(nodeId);
          return next;
        });
      }
      return next;
    });
  }, []);

  /**
   * Expand all nodes
   */
  const expandAll = useCallback(() => {
    setExpandedNodes(new Set());
    setCollapsedNodes(new Set());
    logger.info('All nodes expanded');
  }, []);

  /**
   * Collapse all nodes
   */
  const collapseAll = useCallback(() => {
    setExpandedNodes(new Set());
    logger.info('All nodes collapsed');
  }, []);

  /**
   * Expand specific node and its ancestors
   */
  const expandPath = useCallback((nodeId: string, getAncestors: (id: string) => string[]) => {
    const ancestors = getAncestors(nodeId);
    setExpandedNodes(prev => new Set([...prev, nodeId, ...ancestors]));
    logger.debug(`Path expanded for node: ${nodeId}`);
  }, []);

  /**
   * Check if node is expanded
   */
  const isExpanded = useCallback((nodeId: string) => {
    return expandedNodes.has(nodeId);
  }, [expandedNodes]);

  /**
   * Check if node is collapsed
   */
  const isCollapsed = useCallback((nodeId: string) => {
    return collapsedNodes.has(nodeId);
  }, [collapsedNodes]);

  /**
   * Reset tree state
   */
  const reset = useCallback(() => {
    setSelectedNode(null);
    setExpandedNodes(new Set());
    setCollapsedNodes(new Set());
    logger.info('Tree navigation state reset');
  }, []);

  return {
    selectedNode,
    selectNode,
    expandedNodes,
    collapsedNodes,
    toggleNode,
    expandAll,
    collapseAll,
    expandPath,
    isExpanded,
    isCollapsed,
    reset,
  };
}
