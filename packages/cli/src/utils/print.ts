import chalk from 'chalk'

export const s = {
  ok:   chalk.green('✓'),
  err:  chalk.red('✗'),
  warn: chalk.yellow('⚠'),
  skip: chalk.dim('–'),
  arr:  chalk.dim('→'),
}

export interface SpinnerHandle {
  succeed(msg: string): void
  fail(msg: string): void
  stop(): void
}

/**
 * Minimal terminal spinner. Falls back to plain lines in non-TTY environments (CI, pipes).
 */
export function spinner(text: string): SpinnerHandle {
  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

  if (!process.stdout.isTTY) {
    process.stdout.write(`  ○  ${text}\n`)
    return {
      succeed: (msg) => process.stdout.write(`  ${s.ok}  ${msg}\n`),
      fail:    (msg) => process.stdout.write(`  ${s.err}  ${chalk.red(msg)}\n`),
      stop:    ()    => {},
    }
  }

  let i = 0
  const id = setInterval(() => {
    const frame = frames[i % frames.length] ?? '⠋'
    process.stdout.write(`\r  ${chalk.cyan(frame)}  ${text}`)
    i++
  }, 80)

  const clear = () => process.stdout.write('\r' + ' '.repeat(text.length + 8) + '\r')

  return {
    succeed: (msg) => { clearInterval(id); clear(); process.stdout.write(`  ${s.ok}  ${msg}\n`) },
    fail:    (msg) => { clearInterval(id); clear(); process.stdout.write(`  ${s.err}  ${chalk.red(msg)}\n`) },
    stop:    ()    => { clearInterval(id); clear() },
  }
}

export function divider(): void {
  console.log(chalk.dim('  ─────────────────────────────────────────'))
}
