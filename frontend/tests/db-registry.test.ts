import { describe, it, expect, afterEach } from "vitest"
import fs from "node:fs"
import path from "node:path"
import os from "node:os"
import { saveGeoDb, removeGeoDb, getGeoDbInfo, readGeoDb } from "@/lib/db-registry"

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "pl-geo-test-"))

function fakeMmdb(): Uint8Array {
  return new Uint8Array([0xab, 0xcd, 0xef, 0x4d, 0x61, 0x78, 0x4d, 0x69, 0x6e, 0x64, 0, 0, 0, 0])
}

describe("db-registry", () => {
  afterEach(() => removeGeoDb(TMP))

  it("reports absent when no database is stored", () => {
    expect(getGeoDbInfo(TMP).present).toBe(false)
    expect(readGeoDb(TMP)).toBeNull()
  })

  it("rejects files without the MaxMind magic bytes", () => {
    expect(() => saveGeoDb("dbip-city-lite.mmdb", new Uint8Array([1, 2, 3]), TMP)).toThrow(/MaxMind/)
  })

  it("rejects non-.mmdb names", () => {
    expect(() => saveGeoDb("dbip.txt", fakeMmdb(), TMP)).toThrow(/\.mmdb/)
  })

  it("stores, reports, reads and removes a database", () => {
    saveGeoDb("dbip-city-lite.mmdb", fakeMmdb(), TMP)
    const info = getGeoDbInfo(TMP)
    expect(info.present).toBe(true)
    expect(info.name).toBe("dbip-city-lite.mmdb")
    expect(info.size).toBe(fakeMmdb().length)
    expect(readGeoDb(TMP)?.bytes).toEqual(Buffer.from(fakeMmdb()))
    removeGeoDb(TMP)
    expect(getGeoDbInfo(TMP).present).toBe(false)
  })

  it("replaces an existing database on save", () => {
    saveGeoDb("dbip-city-lite.mmdb", fakeMmdb(), TMP)
    saveGeoDb("dbip-country-lite.mmdb", fakeMmdb(), TMP)
    expect(getGeoDbInfo(TMP).name).toBe("dbip-country-lite.mmdb")
  })
})
