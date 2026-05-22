import fs from 'fs-extra'
import path from 'path'

export type Framework = 'nextjs' | 'react' | 'react-native' | 'node'
export type PackageManager = 'npm' | 'yarn' | 'pnpm' | 'bun'

interface PackageJson {
  dependencies?: Record<string, string>
  devDependencies?: Record<string, string>
}

/**
 * Inspect package.json in `dir` to guess the JS framework in use.
 * Returns 'node' if nothing recognised or no package.json exists.
 */
export async function detectFramework(dir = process.cwd()): Promise<Framework> {
  try {
    const pkgPath = path.join(dir, 'package.json')
    if (!(await fs.pathExists(pkgPath))) return 'node'

    const pkg = (await fs.readJson(pkgPath)) as PackageJson
    const deps: Record<string, string> = {
      ...(pkg.dependencies   ?? {}),
      ...(pkg.devDependencies ?? {}),
    }

    if ('next' in deps)                              return 'nextjs'
    if ('react-native' in deps || 'expo' in deps)   return 'react-native'
    if ('react' in deps)                             return 'react'
  } catch {
    // ignore read errors — fall through to default
  }
  return 'node'
}

/**
 * Detect which package manager is in use by looking for lockfiles.
 */
export async function detectPackageManager(dir = process.cwd()): Promise<PackageManager> {
  if (await fs.pathExists(path.join(dir, 'bun.lockb')))       return 'bun'
  if (await fs.pathExists(path.join(dir, 'pnpm-lock.yaml'))) return 'pnpm'
  if (await fs.pathExists(path.join(dir, 'yarn.lock')))       return 'yarn'
  return 'npm'
}
