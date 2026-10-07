import { describe, expect, it } from 'vitest'
import type { Graph } from '../src/types'
import { filterGraph, graphLayout, layoutGraphNodes, readableViewport } from '../src/lib/graph'

function largeGraph(): Graph {
  const nodes: Graph['nodes'] = [
    { id: 'host', label: 'Authorized host', kind: 'host', evidence_id: 'host-evidence' },
    { id: 'ip', label: 'Observed address', kind: 'ip' },
    ...Array.from({ length: 18 }, (_, i) => ({ id: `endpoint-${i}`, label: `/inventory/${i}`, kind: 'endpoint', evidence_id: `endpoint-evidence-${i}` })),
    ...Array.from({ length: 8 }, (_, i) => ({ id: `resource-${i}`, label: `Resource ${i}`, kind: 'technology' })),
    ...Array.from({ length: 44 }, (_, i) => ({ id: `finding-${i}`, label: `Finding observation ${i}`, kind: 'finding', evidence_id: `finding-evidence-${i}` })),
  ]
  const inventory = nodes.filter((node) => node.kind !== 'finding')
  const edges: Graph['edges'] = [
    ...inventory.slice(1).map((node, i) => ({ id: `inventory-${i}`, source: 'host', target: node.id, label: 'observed' })),
    ...Array.from({ length: 13 }, (_, i) => ({ id: `link-${i}`, source: `endpoint-${i}`, target: `resource-${i % 8}`, label: 'uses' })),
    ...Array.from({ length: 44 }, (_, i) => ({ id: `finding-link-${i}`, source: `endpoint-${i % 18}`, target: `finding-${i}`, label: 'supports' })),
  ]
  return { nodes, edges }
}

describe('attack surface layout and filtering', () => {
  it('defaults to accurate inventory counts without removing underlying finding records or links', () => {
    const graph = largeGraph()
    const inventory = filterGraph(graph, { includeFindings: false })
    expect(graph.nodes).toHaveLength(72)
    expect(graph.edges).toHaveLength(84)
    expect(inventory.nodes).toHaveLength(28)
    expect(inventory.edges).toHaveLength(40)
    const full = filterGraph(graph, { includeFindings: true })
    expect(full.nodes).toHaveLength(72)
    expect(full.edges).toHaveLength(84)
    expect(full.nodes.find((node) => node.id === 'finding-43')?.evidence_id).toBe('finding-evidence-43')
  })

  it('supports explicit finding-type and all-node search while preserving edge endpoint integrity', () => {
    const graph = largeGraph()
    expect(filterGraph(graph, { includeFindings: false, kind: 'finding' }).nodes).toHaveLength(44)
    const search = filterGraph(graph, { includeFindings: true, term: 'Finding observation 43' })
    expect(search.nodes.map((node) => node.id)).toEqual(['finding-43'])
    expect(search.edges).toHaveLength(0)
    const inventory = filterGraph(graph, { includeFindings: false, term: '/inventory' })
    const ids = new Set(inventory.nodes.map((node) => node.id))
    expect(inventory.nodes).toHaveLength(18)
    expect(inventory.edges.every((edge) => ids.has(edge.source) && ids.has(edge.target))).toBe(true)
  })

  it('packs the 44-finding layer into a bounded multi-column grid without overlapping nodes', () => {
    const graph = largeGraph()
    const nodes = layoutGraphNodes(graph.nodes)
    const findings = nodes.filter((node) => node.kind === 'finding')
    expect(new Set(findings.map((node) => node.position.x)).size).toBeGreaterThan(1)
    expect(new Set(findings.map((node) => node.position.y)).size).toBeLessThanOrEqual(graphLayout.maxLayerRows)
    expect(Math.max(...nodes.map((node) => node.position.y)) + graphLayout.nodeHeight).toBeLessThanOrEqual(616)
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i].position, b = nodes[j].position
        expect(Math.abs(a.x - b.x) >= graphLayout.nodeWidth || Math.abs(a.y - b.y) >= graphLayout.nodeHeight).toBe(true)
      }
    }
    expect(layoutGraphNodes(graph.nodes)).toEqual(nodes)
    expect(nodes.find((node) => node.id === 'host')?.evidence_id).toBe('host-evidence')
  })

  it.each([[1144, 560], [358, 450], [1144, 340]])('keeps initial labels readable in a %i by %i viewport instead of fitting everything', (width, height) => {
    const nodes = layoutGraphNodes(filterGraph(largeGraph(), { includeFindings: false }).nodes)
    const viewport = readableViewport(nodes, width, height)
    expect(viewport.zoom).toBeGreaterThanOrEqual(0.9)
    expect(viewport.zoom * graphLayout.labelFontSize).toBeGreaterThanOrEqual(11.7)
    expect(viewport.x).toBeGreaterThanOrEqual(0)
    expect(viewport.y).toBeGreaterThanOrEqual(0)
    expect(Math.max(...nodes.map((node) => node.position.x + graphLayout.nodeWidth)) * viewport.zoom).toBeGreaterThan(width)
  })

  it('still fits and centers a small graph entirely when readable', () => {
    const nodes = layoutGraphNodes(largeGraph().nodes.slice(0, 3))
    const viewport = readableViewport(nodes, 1144, 560)
    expect(viewport.zoom).toBe(1.1)
    for (const node of nodes) {
      expect(node.position.x * viewport.zoom + viewport.x).toBeGreaterThanOrEqual(0)
      expect(node.position.y * viewport.zoom + viewport.y).toBeGreaterThanOrEqual(0)
      expect((node.position.x + graphLayout.nodeWidth) * viewport.zoom + viewport.x).toBeLessThanOrEqual(1144)
      expect((node.position.y + graphLayout.nodeHeight) * viewport.zoom + viewport.y).toBeLessThanOrEqual(560)
    }
    expect(filterGraph({ nodes: [], edges: [] }, { includeFindings: false })).toEqual({ nodes: [], edges: [] })
    expect(readableViewport([], 0, 0)).toEqual({ x: 0, y: 0, zoom: 1 })
  })
})
