// Pure visibility computation for the Investigation Graph. Filtering is
// applied as instant per-element display styles (never a layout or element
// replacement), so search/type filters stay real-time even on large graphs.
//
// Search uses a spotlight model: nodes matching the query are kept, plus
// their direct neighbors (1-hop context, still respecting the type filter),
// so a searched IP shows its connections instead of an isolated dot.
//
// Neighbor policy (counter == rendered, always): type-only filtering isolates
// strictly — no silent context neighbors; search spotlight renders neighbors
// AND the graph's "shown" counter counts exactly what this function returns,
// so the header number and the canvas never disagree.

export function computeVisibleIds(
  all: { data: Record<string, string> }[],
  filterTypes: Set<string>,
  searchQuery: string,
  geoMap?: Map<string, any>,
): Set<string> {
  const searchLower = searchQuery.trim().toLowerCase()
  // "All" chip semantics: "all" in the set, or an empty set (no chip active),
  // both mean every type is visible. The UI toggler and the chip highlight
  // treat size===0 as "All", so the filter must too — previously an empty set
  // hid every node while the "All" chip was lit ("88 nodes · 0 shown").
  const allActive = filterTypes.has("all") || filterTypes.size === 0
  // An element is an edge iff it carries source/target — never by type string:
  // identity edges (B-50) have type "identity", not "edge", and must be
  // treated as edges here or they'd enter byId as pseudo-nodes (they'd match
  // searches and never render the identity pair's edges in the visible set).
  const isEdge = (d: Record<string, string>) => typeof d.source === "string"
  const byId = new Map<string, { data: Record<string, string> }>()
  for (const el of all) if (!isEdge(el.data)) byId.set(el.data.id, el)

  const typeOk = (d: Record<string, string>) => allActive || filterTypes.has(d.type)
  const matchesQuery = (d: Record<string, string>) => {
    if (!searchLower) return true
    const haystack = [d.label, d.info, d.type, d.id].join(" ").toLowerCase()
    if (haystack.includes(searchLower)) return true
    // Also check if searching by country name/code
    if (geoMap && d.type === "country") {
      const cc = d.id.replace("country:", "")
      const name = d.label?.replace(/^[^\s]+\s+/, "") || ""
      if (cc.toLowerCase().includes(searchLower) || name.toLowerCase().includes(searchLower)) return true
    }
    if (geoMap && d.type === "ip") {
      const ip = d.id.replace("ip:", "")
      const g = geoMap.get(ip)
      if (g) {
        const cc = (g.countryCode || "").toLowerCase()
        const name = (g.country || "").toLowerCase()
        if (cc.includes(searchLower) || name.includes(searchLower)) return true
      }
    }
    return false
  }

  // Helper to check if this is a country search
  const isCountrySearch = !!searchLower && (() => {
    if (!geoMap) return false
    // Check if search matches any country
    for (const [ip, g] of geoMap.entries()) {
      if (!g) continue
      const cc = (g.countryCode || "").toLowerCase()
      const name = (g.country || "").toLowerCase()
      if (cc.includes(searchLower) || name.includes(searchLower)) return true
    }
    // Also check country nodes
    for (const el of byId.values()) {
      if (el.data.type === "country") {
        const cc = el.data.id.replace("country:", "").toLowerCase()
        const name = (el.data.label?.replace(/^[^\s]+\s+/, "") || "").toLowerCase()
        if (cc.includes(searchLower) || name.includes(searchLower)) return true
      }
    }
    return false
  })()

  const matching = new Set<string>()
  for (const el of byId.values()) {
    const d = el.data
    if (!matchesQuery(d)) continue
    // For country searches, be permissive about type filters for IPs and countries
    if (isCountrySearch && (d.type === "ip" || d.type === "country")) {
      matching.add(d.id)
      continue
    }
    if (!typeOk(d)) continue
    matching.add(d.id)
  }

  const visible = new Set(matching)
  if (searchLower) {
    for (const el of all) {
      const d = el.data
      if (!isEdge(d)) continue
      if (!matching.has(d.source) && !matching.has(d.target)) continue
      for (const id of [d.source, d.target]) {
        if (visible.has(id)) continue
        const n = byId.get(id)
        if (!n) continue
        // For country searches, always show IPs and countries even if filtered
        if (isCountrySearch && (n.data.type === "ip" || n.data.type === "country")) {
          visible.add(id)
          continue
        }
        if (typeOk(n.data)) visible.add(id)
      }
    }
  }

  for (const el of all) {
    const d = el.data
    if (!isEdge(d)) continue
    if (visible.has(d.source) && visible.has(d.target)) visible.add(d.id)
  }
  return visible
}
