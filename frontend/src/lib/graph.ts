import type { Graph } from '../types'

export const graphLayout = {
  nodeWidth: 240,
  nodeHeight: 104,
  labelFontSize: 13,
  columnGap: 28,
  rowGap: 24,
  layerGap: 80,
  maxLayerRows: 5,
  viewportPadding: 28,
  minReadableZoom: 0.9,
  maxInitialZoom: 1.1,
} as const

export function isFindingKind(kind: string) {
  return kind.toLowerCase() === 'finding'
}

export function filterGraph(graph: Graph, options: { includeFindings: boolean; kind?: string; term?: string }): Graph {
  const term = (options.term || '').trim().toLowerCase()
  const includeFindings = options.includeFindings || isFindingKind(options.kind || '')
  const nodes = graph.nodes.filter((node) =>
    (includeFindings || !isFindingKind(node.kind)) &&
    (!options.kind || node.kind === options.kind) &&
    `${node.label} ${node.url || ''} ${node.id}`.toLowerCase().includes(term),
  )
  const ids = new Set(nodes.map((node) => node.id))
  return { nodes, edges: graph.edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)) }
}

type PositionedNode = Graph['nodes'][number] & { position: { x: number; y: number } }

function layerFor(kind: string) {
  const normalized = kind.toLowerCase()
  if (['host', 'domain', 'subdomain', 'ip'].includes(normalized)) return 0
  if (['endpoint', 'page', 'api', 'form'].includes(normalized)) return 1
  if (['technology', 'script', 'javascript', 'source_map', 'external', 'resource', 'stylesheet'].includes(normalized)) return 2
  return isFindingKind(normalized) ? 3 : 4
}

export function layoutGraphNodes(nodes: Graph['nodes']): PositionedNode[] {
  const layers = new Map<number, Graph['nodes']>()
  for (const node of nodes) {
    const layer = layerFor(node.kind)
    const existing = layers.get(layer) || []
    existing.push(node)
    layers.set(layer, existing)
  }
  let x = 0
  const positioned: PositionedNode[] = []
  for (const [, layer] of [...layers].sort(([a], [b]) => a - b)) {
    const columns = Math.ceil(layer.length / graphLayout.maxLayerRows)
    layer.forEach((node, index) => positioned.push({
      ...node,
      position: {
        x: x + (index % columns) * (graphLayout.nodeWidth + graphLayout.columnGap),
        y: Math.floor(index / columns) * (graphLayout.nodeHeight + graphLayout.rowGap),
      },
    }))
    x += columns * graphLayout.nodeWidth + (columns - 1) * graphLayout.columnGap + graphLayout.layerGap
  }
  return positioned
}

export function readableViewport(nodes: readonly { position: { x: number; y: number } }[], width: number, height: number) {
  if (!nodes.length || width <= 0 || height <= 0) return { x: 0, y: 0, zoom: 1 }
  const minX = Math.min(...nodes.map((node) => node.position.x))
  const minY = Math.min(...nodes.map((node) => node.position.y))
  const boundsWidth = Math.max(...nodes.map((node) => node.position.x)) + graphLayout.nodeWidth - minX
  const boundsHeight = Math.max(...nodes.map((node) => node.position.y)) + graphLayout.nodeHeight - minY
  const padding = Math.min(graphLayout.viewportPadding, width / 10, height / 10)
  const fittedZoom = Math.min((width - padding * 2) / boundsWidth, (height - padding * 2) / boundsHeight, graphLayout.maxInitialZoom)
  const zoom = Math.max(graphLayout.minReadableZoom, fittedZoom)
  return {
    x: boundsWidth * zoom <= width - padding * 2 ? (width - boundsWidth * zoom) / 2 - minX * zoom : padding - minX * zoom,
    y: boundsHeight * zoom <= height - padding * 2 ? (height - boundsHeight * zoom) / 2 - minY * zoom : padding - minY * zoom,
    zoom,
  }
}
