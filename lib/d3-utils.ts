import * as d3 from 'd3';
import { Technique, PWN_TECHNIQUES } from './pwn-data';

export interface TreeNode extends d3.HierarchyNode<Technique> {
  x: number;
  y: number;
  x0?: number;
  y0?: number;
}

export interface TreeLink {
  source: TreeNode;
  target: TreeNode;
}

export const buildHierarchy = (rootId: string, techniques: Record<string, Technique>) => {
  const buildNode = (id: string): Technique & { children?: (Technique & { children?: any })[] } => {
    const tech = techniques[id];
    if (!tech) {
      // Return empty placeholder if technique doesn't exist
      return {
        id,
        name: '',
        category: 'leaf',
        stack: [],
        format: [],
        heap: [],
        sandbox: [],
        description: '',
        prerequisites: [],
        constraints: [],
        blueprint: '',
      };
    }

    const children = tech.children
      ?.filter((childId) => techniques[childId])
      .map((childId) => buildNode(childId));
    return {
      ...tech,
      ...(children && children.length > 0 && { children }),
    };
  };

  return buildNode(rootId);
};

export const createTreeLayout = (
  width: number,
  height: number,
  data: any,
): [d3.HierarchyNode<any>, d3.Link<d3.HierarchyNode<any>>[], TreeNode[]] => {
  const tree = d3.tree<Technique>().size([height, width - 200]);
  const root = d3.hierarchy(data);
  tree(root);

  // Cast to our TreeNode type with coordinates
  const nodes = root.descendants() as TreeNode[];
  const links = root.links() as d3.Link<TreeNode>[];

  return [root, links as any, nodes];
};

export const getCategoryColor = (category: string): string => {
  switch (category) {
    case 'root':
      return '#00d9ff'; // neon cyan
    case 'recon':
      return '#00ff41'; // neon lime
    case 'technique':
      return '#7c3aed'; // neon purple
    case 'mitigation':
      return '#ff6b35'; // neon orange
    case 'leaf':
      return '#ff006e'; // neon magenta
    default:
      return '#666666'; // dark gray
  }
};

export const getCategoryGlow = (category: string): string => {
  const color = getCategoryColor(category);
  // Neon glow effect for light mode
  return `drop-shadow(0 0 2px ${color}) drop-shadow(0 0 8px ${color}80) drop-shadow(0 0 16px ${color}40)`;
};

export const calculateNodeRadius = (category: string): number => {
  switch (category) {
    case 'root':
      return 10;
    case 'recon':
      return 8;
    case 'technique':
      return 6;
    case 'leaf':
      return 5;
    default:
      return 6;
  }
};

export interface NodeInfo {
  id: string;
  label: string;
  x: number;
  y: number;
  radius: number;
}

export const getNodeInfo = (node: TreeNode): NodeInfo => ({
  id: node.data.id,
  label: node.data.name,
  x: node.y,
  y: node.x,
  radius: calculateNodeRadius(node.data.category),
});

export const buildLinkPath = (link: { source: TreeNode; target: TreeNode }): string => {
  return `
    M${link.source.y},${link.source.x}
    C${(link.source.y + link.target.y) / 2},${link.source.x}
     ${(link.source.y + link.target.y) / 2},${link.target.x}
     ${link.target.y},${link.target.x}
  `;
};

export const isNodeHighlighted = (
  nodeId: string,
  searchMatches: Set<string>,
  pathHighlight: Set<string>,
): boolean => {
  if (searchMatches.size === 0) return false;
  return searchMatches.has(nodeId) || pathHighlight.has(nodeId);
};

export const getNodeOpacity = (
  nodeId: string,
  searchMatches: Set<string>,
  pathHighlight: Set<string>,
): number => {
  if (searchMatches.size === 0) return 1;
  return pathHighlight.has(nodeId) ? 1 : 0.2;
};

export const getLinkOpacity = (
  sourceId: string,
  targetId: string,
  searchMatches: Set<string>,
  pathHighlight: Set<string>,
): number => {
  if (searchMatches.size === 0) return 0.3;
  return pathHighlight.has(sourceId) && pathHighlight.has(targetId) ? 0.6 : 0.1;
};
