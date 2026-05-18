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

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const container = containerRef.current;
    const width = container.clientWidth;
    const height = container.clientHeight;

    // Build hierarchy from root
    const hierarchyData = buildHierarchy('root', filteredTechniques);

    // Create tree layout
    const tree = d3.tree<Technique>().size([height, width - 200]);
    const root = d3.hierarchy(hierarchyData);
    tree(root);

    const svg = d3.select(svgRef.current);
    svg.attr('width', width).attr('height', height);

    // Clear previous content
    svg.selectAll('*').remove();

    // Create main group
    const g = svg.append('g').attr('class', 'tree-group');

    // Add zoom behavior
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    // Reset zoom on double click
    svg.on('dblclick.zoom', function (event) {
      svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
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
    const truncateText = (text: string, maxLength: number = 12): string => {
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
        return d.data.category === 'root' ? '12px' : '10px';
      })
      .style('opacity', (d: any) => getNodeOpacity(d.data.id, searchMatches, pathHighlight))
      .text((d: any) => truncateText(d.data.name, 12))
      .append('title')
      .text((d: any) => d.data.name);

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
  }, [filteredTechniques, searchMatches, pathHighlight, selectedNode, onNodeSelect]);

  return (
    <div ref={containerRef} className="pwn-canvas-area">
      <svg ref={svgRef} className="pwn-canvas" />
    </div>
  );
}
