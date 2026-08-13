import { describe, it, expect } from "vitest"
import { checkGeoDb, installedGeoDbFile } from "../scripts/verify-geoip.mjs"

// Guard: the repo ships no .mmdb (DB-IP Lite is ~130 MB, fetched per machine),
// so the check only runs when an operator has installed one.
const hasDb = installedGeoDbFile() !== ""

describe("installed GeoIP DB sanity", () => {
  it.skipIf(!hasDb)("known anchors resolve to the countries DB-IP assigns", () => {
    const issues = checkGeoDb(installedGeoDbFile())
    expect(issues).toEqual([])
  })
})