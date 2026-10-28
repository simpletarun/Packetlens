"use client"

import { useRef, useMemo } from "react"
import { Canvas, useFrame } from "@react-three/fiber"

import * as THREE from "three"

// suppress harmless THREE.Clock deprecation from R3F internals
if (typeof window !== "undefined") {
  const _warn = console.warn
  console.warn = (...args: unknown[]) => { if (typeof args[0] === "string" && args[0].includes("THREE.Clock")) return; _warn(...args) }
}

const NUM_NODES = 10
const RADIUS = 3

// Deterministic pseudo-random values so the scene is render-pure (no Math.random
// during render — React purity rule). Same seed => same scene across re-renders.
function seeded(i: number): number {
  const x = Math.sin(i * 12.9898 + 78.233) * 43758.5453
  return x - Math.floor(x)
}

function randomVec3(scale = 1, seed = 0) {
  return new THREE.Vector3(
    (seeded(seed + 1) - 0.5) * scale * 2,
    (seeded(seed + 2) - 0.5) * scale * 2,
    (seeded(seed + 3) - 0.5) * scale * 2,
  )
}

function Node({ position, color }: { position: THREE.Vector3; color: string }) {
  const ref = useRef<THREE.Mesh>(null)
  const t = useRef(0)
  useFrame((_state, delta) => {
    t.current += delta
    if (ref.current) {
      ref.current.position.y += Math.sin(t.current * 0.5 + position.x) * 0.002
      ref.current.position.x += Math.cos(t.current * 0.3 + position.z) * 0.002
    }
  })
  return (
    <mesh ref={ref} position={position}>
      <sphereGeometry args={[0.12, 16, 16]} />
      <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.3} />
    </mesh>
  )
}

function NetworkLines({ points, color }: { points: THREE.Vector3[]; color: string }) {
  const lines = useMemo(() => {
    const result: { key: string; start: THREE.Vector3; end: THREE.Vector3 }[] = []
    for (let i = 0; i < points.length; i++) {
      for (let j = i + 1; j < points.length; j++) {
        const dist = points[i].distanceTo(points[j])
        if (dist < 4) {
          result.push({ key: `${i}-${j}`, start: points[i], end: points[j] })
        }
      }
    }
    return result
  }, [points])

  return (
    <>
      {lines.map((l) => {
        const mid = new THREE.Vector3().addVectors(l.start, l.end).multiplyScalar(0.5)
        const dir = new THREE.Vector3().subVectors(l.end, l.start)
        const len = dir.length()
        return (
          <mesh key={l.key} position={mid}>
            <boxGeometry args={[len, 0.008, 0.008]} />
            <meshBasicMaterial color={color} transparent opacity={0.15} />
          </mesh>
        )
      })}
    </>
  )
}

function Particles({ count = 200 }) {
  const ref = useRef<THREE.Points>(null)
  const t = useRef(0)

  useFrame((_state, delta) => {
    t.current += delta
    if (ref.current) {
      ref.current.rotation.y = t.current * 0.02
      ref.current.rotation.x = Math.sin(t.current * 0.01) * 0.1
    }
  })

  const geometry = useMemo(() => {
    const pos = new Float32Array(count * 3)
    for (let i = 0; i < count * 3; i++) {
      pos[i] = (seeded(i) - 0.5) * 20
    }
    const g = new THREE.BufferGeometry()
    g.setAttribute("position", new THREE.BufferAttribute(pos, 3))
    return g
  }, [count])

  return (
    <points ref={ref} geometry={geometry}>
      <pointsMaterial size={0.04} color="#6366f1" transparent opacity={0.4} sizeAttenuation />
    </points>
  )
}

const SCENE_COLORS = ["#6366f1", "#8b5cf6", "#3b82f6", "#06b6d4"]

function Scene() {
  const points = useMemo(() => Array.from({ length: NUM_NODES }, (_, i) => randomVec3(RADIUS, i * 7)), [])
  const nodeColors = useMemo(() => {
    const result: string[] = []
    for (let i = 0; i < points.length; i++) {
      result.push(SCENE_COLORS[(i * 3 + 1) % SCENE_COLORS.length])
    }
    return result
  }, [points])

  return (
    <>
      <ambientLight intensity={0.4} />
      <pointLight position={[5, 5, 5]} intensity={0.8} />
      <pointLight position={[-5, -5, -5]} intensity={0.4} />
      <NetworkLines points={points} color="#6366f1" />
      {points.map((p, i) => (
        <Node key={i} position={p} color={nodeColors[i]} />
      ))}
      <Particles count={300} />
    </>
  )
}

export function NetworkScene() {
  return (
    <div className="fixed inset-0 -z-10 pointer-events-none">
      <Canvas camera={{ position: [0, 0, 8], fov: 50 }}>
        <Scene />
      </Canvas>
    </div>
  )
}
