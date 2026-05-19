'use client';

import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Technique, PWN_TECHNIQUES } from '@/lib/pwn-data';
import {
  buildHierarchy,
  createTreeLayout,
  getCategoryColor,
  getCategoryGlow,
  calculateNodeRadius,
  buildLinkPath,
  isNodeHighlighted,
  getNodeOpacity,
  getLinkOpacity,
} from '@/lib/d3-utils';

interface PwnTreeCanvasProps {
  selectedNode: Technique | null;
  onNodeSelect: (technique: Technique) => void;
  searchMatches: Set<string>;
  pathHighlight: Set<string>;
  filteredTechniques: Record<string, Technique>;
}

export function PwnTreeCanvas({
  selectedNode,
  onNodeSelect,
  searchMatches,
  pathHighlight,
  filteredTechniques,
}: PwnTreeCanvasProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const currentZoomRef = useRef<d3.ZoomTransform | null>(null);
  const [collapsedNodes, setCollapsedNodes] = useState<Set<string>>(() => {
    const defaultCollapsed = new Set<string>();
    Object.values(PWN_TECHNIQUES).forEach(tech => {
      // Collapse everything with children except the absolute root
      if (tech.children && tech.children.length > 0 && tech.id !== 'root') {
        defaultCollapsed.add(tech.id);
      }
    });
    return defaultCollapsed;
  });

  const handleExpandAll = () => setCollapsedNodes(new Set());
  
  const handleCollapseAll = () => {
    const allCollapsed = new Set<string>();
    Object.values(PWN_TECHNIQUES).forEach(tech => {
      if (tech.children && tech.children.length > 0 && tech.id !== 'root') {
        allCollapsed.add(tech.id);
      }
    });
    setCollapsedNodes(allCollapsed);
  };

  const handleToggleCollapse = (nodeId: string) => {
    setCollapsedNodes((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) next.delete(nodeId);
      else next.add(nodeId);
      return next;
    });
  };

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const container = containerRef.current;
    const width = container.clientWidth;
    const height = container.clientHeight;

    // Build hierarchy from root
    const hierarchyData = buildHierarchy('root', filteredTechniques, collapsedNodes);

    // Create tree layout with fixed node sizes to prevent squishing
    const dx = 60; // Vertical spacing
    const dy = 240; // Horizontal spacing
    const tree = d3.tree<Technique>().nodeSize([dx, dy]);
    const root = d3.hierarchy(hierarchyData);
    tree(root);

    const svg = d3.select(svgRef.current);
    svg.attr('width', width).attr('height', height);

    // Clear previous content
    svg.selectAll('*').remove();

    // Create main group
    const g = svg.append('g').attr('class', 'tree-group');

    // Initial transform to place root vertically centered and slightly offset from left
    const initialTransform = d3.zoomIdentity.translate(120, height / 2);

    // Add zoom behavior
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
        currentZoomRef.current = event.transform;
      });

    const transformToApply = currentZoomRef.current || initialTransform;

    svg.call(zoom);
    svg.call(zoom.transform, transformToApply);

    // Reset zoom on double click
    svg.on('dblclick.zoom', function (event) {
      svg.transition().duration(750).call(zoom.transform, initialTransform);
    });

    // Draw links first (so they appear behind nodes)
    const links = root.links();
    g.selectAll('.link')
      .data(links)
      .join('path')
      .attr('class', 'pwn-link')
      .attr('d', (d: any) => {
        const source = d.source;
        const target = d.target;
        return `
          M${source.y},${source.x}
          C${(source.y + target.y) / 2},${source.x}
           ${(source.y + target.y) / 2},${target.x}
           ${target.y},${target.x}
        `;
      })
      .style('stroke-opacity', (d: any) => {
        return getLinkOpacity(d.source.data.id, d.target.data.id, searchMatches, pathHighlight);
      })
      .style('stroke-width', (d: any) => {
        const isHighlighted =
          pathHighlight.has(d.source.data.id) && pathHighlight.has(d.target.data.id);
        return isHighlighted ? 3 : 2;
      });

    // Helper function to truncate text
    const truncateText = (text: string | undefined, maxLength: number = 40): string => {
      if (!text) return '';
      return text.length > maxLength ? text.substring(0, maxLength - 1) + '…' : text;
    };

    // Draw nodes
    const nodes = root.descendants();
    const nodeGroups = g
      .selectAll('.node')
      .data(nodes, (d: any) => d.data.id)
      .join('g')
      .attr('class', 'pwn-node-group')
      .attr('transform', (d: any) => `translate(${d.y},${d.x})`);

    // Node circles
    nodeGroups
      .append('circle')
      .attr('class', 'pwn-node-circle')
      .attr('r', (d: any) => calculateNodeRadius(d.data.category))
      .attr('fill', (d: any) => getCategoryColor(d.data.category))
      .style('opacity', (d: any) => getNodeOpacity(d.data.id, searchMatches, pathHighlight))
      .style('filter', (d: any) => {
        const glow = getCategoryGlow(d.data.category);
        const isHighlighted = isNodeHighlighted(d.data.id, searchMatches, pathHighlight);
        return isHighlighted ? `drop-shadow(0 0 12px ${glow})` : `drop-shadow(0 0 6px ${glow})`;
      })
      .on('click', function (event, d: any) {
        event.stopPropagation();
        onNodeSelect(d.data);
      })
      .on('mouseenter', function (event, d: any) {
        // Highlight node on hover
        d3.select(this).style('filter', `drop-shadow(0 0 16px ${getCategoryGlow(d.data.category)})`);
      })
      .on('mouseleave', function (event, d: any) {
        const isHighlighted = isNodeHighlighted(d.data.id, searchMatches, pathHighlight);
        const glow = getCategoryGlow(d.data.category);
        d3.select(this).style(
          'filter',
          isHighlighted ? `drop-shadow(0 0 12px ${glow})` : `drop-shadow(0 0 6px ${glow})`,
        );
      });

    // Node labels
    nodeGroups
      .append('text')
      .attr('class', 'pwn-label')
      .attr('dy', (d: any) => {
        const radius = calculateNodeRadius(d.data.category);
        return -(radius + 12);
      })
      .attr('text-anchor', 'middle')
      .style('font-size', (d: any) => {
        return d.data.category === 'root' ? '12px' : '10.5px';
      })
      .style('opacity', (d: any) => getNodeOpacity(d.data.id, searchMatches, pathHighlight))
      .text((d: any) => truncateText(d.data.name, 40))
      .append('title')
      .text((d: any) => d.data.name);

    // Expand/Collapse toggles
    const toggleGroups = nodeGroups
      .filter((d: any) => d.data._hasChildren)
      .append('g')
      .attr('class', 'pwn-node-toggle')
      .attr('transform', (d: any) => {
        const radius = calculateNodeRadius(d.data.category);
        return `translate(${radius + 6}, 0)`;
      })
      .style('cursor', 'pointer')
      .on('click', function (event, d: any) {
        event.stopPropagation();
        handleToggleCollapse(d.data.id);
      });

    toggleGroups
      .append('circle')
      .attr('r', 5)
      .attr('fill', '#1e293b')
      .attr('stroke', (d: any) => getCategoryColor(d.data.category))
      .attr('stroke-width', 1);

    toggleGroups
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', '0.3em')
      .style('font-size', '8px')
      .style('font-weight', 'bold')
      .style('fill', (d: any) => getCategoryColor(d.data.category))
      .text((d: any) => (collapsedNodes.has(d.data.id) ? '+' : '-'));

    // Highlight selected node
    if (selectedNode) {
      nodeGroups
        .select('circle')
        .style('stroke', (d: any) => {
          return d.data.id === selectedNode.id ? '#06b6d4' : 'none';
        })
        .style('stroke-width', (d: any) => {
          return d.data.id === selectedNode.id ? 2 : 0;
        });
    }
  }, [filteredTechniques, searchMatches, pathHighlight, selectedNode, onNodeSelect, collapsedNodes]);

  return (
    <div ref={containerRef} className="pwn-canvas-area" style={{ position: 'relative' }}>
      <div className="absolute top-4 right-4 flex gap-2 z-10">
        <button 
          onClick={handleExpandAll} 
          className="px-3 py-1.5 bg-slate-800/80 backdrop-blur text-cyan-400 border border-cyan-500/30 rounded text-xs hover:bg-slate-700 transition-colors shadow-lg"
        >
          Expand All
        </button>
        <button 
          onClick={handleCollapseAll} 
          className="px-3 py-1.5 bg-slate-800/80 backdrop-blur text-cyan-400 border border-cyan-500/30 rounded text-xs hover:bg-slate-700 transition-colors shadow-lg"
        >
          Collapse All
        </button>
      </div>
      <svg ref={svgRef} className="pwn-canvas" />
    </div>
  );
}
