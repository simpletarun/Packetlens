// Re-applies the canvas2svg fix inside the bundled cytoscape-svg plugin.
// The plugin replays cytoscape's canvas calls into an SVG via canvas2svg;
// when a fill()/stroke() lands while the context's current element is a
// leftover <text> node (created by fillText), canvas2svg console.errors
// "Attempted to apply path command to node text" and drops the node body
// from the exported SVG. The patch makes __applyCurrentDefaultPath start a
// fresh path instead — exactly what a real canvas does. Idempotent: a fresh
// npm install wipes the fix, this restores it.

import { existsSync, readFileSync, writeFileSync } from "node:fs"
import { join, dirname } from "node:path"
import { fileURLToPath } from "node:url"

const target = join(dirname(fileURLToPath(import.meta.url)), "..", "node_modules", "cytoscape-svg", "cytoscape-svg.js")
if (!existsSync(target)) process.exit(0)

const oldCode = 'r.prototype.__applyCurrentDefaultPath=function(){var t=this.__currentElement;"path"===t.nodeName?t.setAttribute("d",this.__currentDefaultPath):console.error("Attempted to apply path command to node",t.nodeName)}'
const newCode = 'r.prototype.__applyCurrentDefaultPath=function(){var t=this.__currentElement;if("path"!==t.nodeName){this.beginPath();t=this.__currentElement}t.setAttribute("d",this.__currentDefaultPath)}'

const src = readFileSync(target, "utf8")
if (src.includes(newCode)) process.exit(0)
if (!src.includes(oldCode)) process.exit(0)
writeFileSync(target, src.replace(oldCode, newCode))
