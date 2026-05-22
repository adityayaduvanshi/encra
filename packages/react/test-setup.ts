/**
 * Runs before jsdom environment is initialised. Ensures that libsodium's
 * from_string() produces Uint8Arrays that pass its own instanceof check,
 * even after jsdom replaces the global TextEncoder with its own version.
 *
 * Root cause: libsodium CJS IIFE captures the Node.js Uint8Array at load time,
 * but jsdom replaces the global TextEncoder afterwards, which may produce typed
 * arrays that don't satisfy the pre-captured instanceof check.
 */
import { vi } from 'vitest'

const NodeUint8Array = Uint8Array

// After every test, ensure Uint8Array instanceof checks still use the Node global
vi.stubGlobal('Uint8Array', NodeUint8Array)
