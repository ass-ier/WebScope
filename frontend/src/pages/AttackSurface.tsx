import { useCallback, useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { Background, BackgroundVariant, ControlButton, Controls, Handle, MiniMap, Position, ReactFlow, useNodesState, useReactFlow, useStore } from '@xyflow/react'
import type { Node, NodeProps } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import type { Graph } from '../types'
import { assessmentPath, useApi } from '../lib/api'
import { filterGraph, graphLayout, isFindingKind, layoutGraphNodes, readableViewport } from '../lib/graph'
import { Badge, CheckField, DataTable, Empty, Field, PageHeader, QueryState, RecordLink, Section, human } from '../components/ui'

type ObservationData = Graph['nodes'][number] & Record<string, unknown>
type ObservationNode = Node<ObservationData, 'observation'>
function Observation({ data, selected }: NodeProps<ObservationNode>) {
  return <div className={`graph-node ${selected ? 'selected' : ''}`}>
    <Handle type="target" position={Position.Left} />
    <span className="graph-kind">{human(data.kind)}</span><strong title={data.label} style={{ fontSize: graphLayout.labelFontSize }}>{data.label}</strong>
    {data.evidence_id && <RecordLink id={data.evidence_id}>Inspect evidence</RecordLink>}
    <Handle type="source" position={Position.Right} />
  </div>
}
const nodeTypes = { observation: Observation }

function ReadableViewport({ initialNodes }: { initialNodes: ObservationNode[] }) {
  const width = useStore((state) => state.width)
  const height = useStore((state) => state.height)
  const { getNodes, setViewport, viewportInitialized } = useReactFlow<ObservationNode>()
  const frame = useCallback((nodes: ObservationNode[]) => {
    if (viewportInitialized && width > 0 && height > 0) void setViewport(readableViewport(nodes, width, height))
  }, [width, height, setViewport, viewportInitialized])
  useEffect(() => { frame(initialNodes) }, [frame, initialNodes])
  return <Controls showInteractive={false} fitViewOptions={{ padding: 0.15, minZoom: 0.15, maxZoom: graphLayout.maxInitialZoom }} aria-label="Graph zoom and fit controls">
    <ControlButton onClick={() => frame(getNodes())} title="Readable view" aria-label="Readable view"><span aria-hidden="true">Aa</span></ControlButton>
  </Controls>
}

function GraphView({ graph, compact = false }: { graph: Graph; compact?: boolean }) {
  const [kind, setKind] = useState('')
  const [term, setTerm] = useState('')
  const [includeFindings, setIncludeFindings] = useState(false)
  const kinds = [...new Set(graph.nodes.map((node) => node.kind))].sort()
  const findingCount = graph.nodes.filter((node) => isFindingKind(node.kind)).length
  const { nodes, edges } = useMemo(() => {
    const visible = filterGraph(graph, { kind, term, includeFindings })
    const nodes: ObservationNode[] = layoutGraphNodes(visible.nodes).map(({ position, ...data }) => ({
      id: data.id, type: 'observation', position, data,
      style: { width: graphLayout.nodeWidth, height: graphLayout.nodeHeight },
    }))
    return { nodes, edges: visible.edges.map((edge) => ({ ...edge, type: 'smoothstep', style: { stroke: '#536577' }, labelStyle: { fill: '#c3ced9', fontSize: 11 }, labelBgStyle: { fill: '#171e26' } })) }
  }, [graph, kind, term, includeFindings])
  const [displayNodes, setDisplayNodes, onNodesChange] = useNodesState(nodes)
  useEffect(() => { setDisplayNodes(nodes) }, [nodes, setDisplayNodes])
  if (!graph.nodes.length) return <Empty title="No attack surface mapped">Add endpoint inventory, import OpenAPI, or explicitly run authorized discovery. The graph is built from persisted observations.</Empty>
  return <>{!compact && <div className="graph-toolbar"><Field label="Node type"><select value={kind} onChange={(e) => { setKind(e.target.value); if (isFindingKind(e.target.value)) setIncludeFindings(true) }}><option value="">{includeFindings ? 'All node types' : 'All inventory node types'}</option>{kinds.map((k) => <option key={k} value={k}>{human(k)}</option>)}</select></Field><Field label="Find a node"><input type="search" value={term} onChange={(e) => setTerm(e.target.value)} placeholder="Filter nodes in this view…" /></Field></div>}
    <div className="graph-view-options">{!compact && <CheckField label={`Include finding nodes (${findingCount})`} checked={includeFindings} disabled={findingCount === 0} onChange={(next) => { setIncludeFindings(next); if (!next && isFindingKind(kind)) setKind('') }} />}<span className="muted" role="status">{compact ? 'Inventory · ' : ''}{nodes.length} of {graph.nodes.length} nodes · {edges.length} of {graph.edges.length} relationships</span></div>
    {nodes.length ? <div className={`graph-canvas ${compact ? 'compact' : ''}`} role="region" aria-label="Interactive attack surface graph"><ReactFlow nodes={displayNodes} onNodesChange={onNodesChange} edges={edges} nodeTypes={nodeTypes} minZoom={0.15} maxZoom={2.5} colorMode="dark" nodesDraggable nodesConnectable={false} elementsSelectable deleteKeyCode={null} proOptions={{ hideAttribution: false }}>
      <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#303a45" />
      <ReadableViewport initialNodes={nodes} />
      <MiniMap zoomable pannable nodeColor="#647c95" maskColor="rgba(16,20,25,0.65)" ariaLabel="Attack surface minimap" />
    </ReactFlow></div> : <Empty title="No matching inventory or included finding nodes">{compact ? 'Open the full attack surface to inspect all node types.' : 'Clear the filters or include finding nodes. Every node remains searchable in the index below.'}</Empty>}
    <p className="field-hint">Pan or use the minimap to explore beyond the viewport. Fit shows the full graph; Readable view (Aa) restores working zoom. {compact ? 'Open the full attack surface to include findings and filter all nodes.' : 'Include findings to search all node types. Tab focuses nodes and controls; arrow keys move selected nodes.'} Evidence links never open the target.</p>
    {!compact && <Section title="All mapped observations"><DataTable rows={graph.nodes} label="Graph observations" search={(r) => `${r.label} ${r.kind} ${r.id}`} columns={[
      { key: 'label', label: 'Observation', render: (r) => <span className="mono">{r.label}</span> },
      { key: 'kind', label: 'Kind', sort: (r) => r.kind, render: (r) => <Badge value={r.kind} /> },
      { key: 'evidence', label: 'Source evidence', render: (r) => r.evidence_id ? <RecordLink id={r.evidence_id} /> : 'Assessment boundary' },
    ]} /></Section>}
  </>
}
export function GraphPreview({ assessmentId }: { assessmentId: string }) {
  const query = useApi<Graph>(assessmentPath(assessmentId, 'graph'))
  return <QueryState query={query}>{(data) => <GraphView graph={data} compact />}</QueryState>
}
export default function AttackSurface() {
  const { assessmentId = '' } = useParams()
  const query = useApi<Graph>(assessmentPath(assessmentId, 'graph'))
  return <><PageHeader title="Attack surface" description="Trace hosts, endpoints, APIs, and technologies back to their source observations." /><QueryState query={query}>{(data) => <GraphView graph={data} />}</QueryState></>
}
