export const meta = {
  name: 'spec-to-landing',
  description: 'Spec to landing: check spec, approval gate, implement plan tasks, review, fix, gate, prepare landing (never pushes)',
  whenToUse: 'After a spec and plan exist. Pass {specPath, planPath, repo, branch, boardCard, approved, startTask, endTask}. Stops at every human gate and returns {stopped: ...}.',
  phases: [
    { title: 'Brainstorm', detail: 'check the spec exists (the conversation itself runs in main)' },
    { title: 'Approve', detail: 'human gate: needs args.approved === true' },
    { title: 'Implement', detail: 'plan tasks, sequential, one agent each, commit per task' },
    { title: 'Review', detail: 'two fresh reviewers per task: correctness and security' },
    { title: 'Fix', detail: 'up to 3 fix rounds per task, then re-review' },
    { title: 'Gate', detail: 'fmt, vet, tests, cross-build, crew verify, whole-branch review' },
    { title: 'Land', detail: 'prepare landing summary only: no push, merge or PR' },
  ],
}

// ---- script body ----
// Claude's calls (not decided by the user): tasks run sequentially on ONE branch because they share
// interfaces; Brainstorm and Approve cannot be automated (a human answers), so they only check and
// stop; Land never pushes or merges, the main session asks the owner first; board updates are small
// low-effort agents; no stage ever prints a token or email.

const ATTRIBUTION = 'Claude-Session: https://claude.ai/code/session_01WfiMadwvdH4MdTkWjNV5TC'
const BOARD = 'C:\\repos\\claude-memories\\Boards\\Board.md'
const NO_SECRETS = 'Never print, log or commit a token, password or email address.'

const SPEC_SCHEMA = {
  type: 'object',
  properties: { exists: { type: 'boolean' }, summary: { type: 'string' } },
  required: ['exists', 'summary'],
}
const TASKS_SCHEMA = {
  type: 'object',
  properties: {
    tasks: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          title: { type: 'string' },
          text: { type: 'string' },
          dependsOnSpike: { type: 'boolean' },
          needsHuman: { type: 'boolean' },
        },
        required: ['id', 'title', 'text', 'dependsOnSpike', 'needsHuman'],
      },
    },
  },
  required: ['tasks'],
}
const EXISTS_SCHEMA = {
  type: 'object',
  properties: { exists: { type: 'boolean' } },
  required: ['exists'],
}
const IMPL_SCHEMA = {
  type: 'object',
  properties: {
    sha: { type: 'string' },
    testsPassed: { type: 'boolean' },
    summary: { type: 'string' },
  },
  required: ['sha', 'testsPassed', 'summary'],
}
const REVIEW_SCHEMA = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['pass', 'fail'] },
    findings: { type: 'array', items: { type: 'string' } },
  },
  required: ['verdict', 'findings'],
}
const GATE_SCHEMA = {
  type: 'object',
  properties: {
    passed: { type: 'boolean' },
    commands: {
      type: 'array',
      items: {
        type: 'object',
        properties: { cmd: { type: 'string' }, exit: { type: 'number' }, summary: { type: 'string' } },
        required: ['cmd', 'exit', 'summary'],
      },
    },
  },
  required: ['passed', 'commands'],
}
const LAND_SCHEMA = {
  type: 'object',
  properties: {
    branch: { type: 'string' },
    shas: { type: 'array', items: { type: 'string' } },
    diffStat: { type: 'string' },
    gateEvidence: { type: 'string' },
    openRisks: { type: 'array', items: { type: 'string' } },
  },
  required: ['branch', 'shas', 'diffStat', 'gateEvidence', 'openRisks'],
}

const a = args || {}
const repo = a.repo
const branch = a.branch
const startTask = typeof a.startTask === 'number' ? a.startTask : 0
const endTask = typeof a.endTask === 'number' ? a.endTask : Infinity

// Board update: small low-effort agent. Moves status only as far as the evidence goes.
async function board(phaseTitle, label, event, fact) {
  if (!a.boardCard) {
    log('board skipped (no args.boardCard): ' + event)
    return null
  }
  return agent(
    'Update the Obsidian Kanban board file ' + BOARD + ' for card "' + a.boardCard + '". ' +
      'First read the vault rules in C:\\repos\\claude-memories\\CLAUDE.md (ASCII only, frontmatter contract) and follow them. ' +
      'Event: ' + event + '. Fact comment to add under the card: ' + fact + '. ' +
      'Move the card only as far as this evidence goes (merged is not deployed is not verified). ' +
      'Edit only that card. ' + NO_SECRETS + ' Return the string "ok" when done.',
    { label: label, phase: phaseTitle, effort: 'low' }
  )
}

// ---- 1 Brainstorm ----
phase('Brainstorm')
const spec = await agent(
  'Read the file ' + a.specPath + ' (it may be missing). Return exists=true with a 3-sentence summary of what it specifies, ' +
    'or exists=false with summary "missing". Modify nothing.',
  { label: 'check spec', phase: 'Brainstorm', schema: SPEC_SCHEMA, effort: 'low' }
)
if (!spec || !spec.exists) {
  return { stopped: 'needs-brainstorm', instruction: 'run superpowers:brainstorming in the main session' }
}
log('spec found: ' + spec.summary)

// ---- 2 Approve ----
phase('Approve')
if (a.approved !== true) {
  return {
    stopped: 'needs-approval',
    instruction: 'main asks the owner via AskUserQuestion, then re-invokes with approved:true',
    specSummary: spec.summary,
  }
}
log('approved by owner')

// ---- 3 Implement (plan parsing) ----
phase('Implement')
const parsed = await agent(
  'Read the implementation plan ' + a.planPath + '. Return its tasks in plan order. For each: id (the task number as a string), ' +
    'title, text (the complete task section verbatim, steps and interfaces included), dependsOnSpike (true if it says to finalise or ' +
    'change after the spike), needsHuman (true if it needs the owner to act, such as real account logins or approvals). Modify nothing.',
  { label: 'parse plan', phase: 'Implement', schema: TASKS_SCHEMA }
)
if (!parsed || !parsed.tasks || parsed.tasks.length === 0) {
  return { stopped: 'plan-unparseable', planPath: a.planPath }
}

const done = []
for (const task of parsed.tasks) {
  const n = Number(task.id)
  if (n < startTask) {
    log('skipping task ' + task.id + ' (before startTask ' + startTask + ')')
    continue
  }
  if (n > endTask) {
    log('stopping before task ' + task.id + ' (beyond endTask ' + endTask + ')')
    return { stopped: 'needs-human', reason: 'beyond-endTask', task: task, done: done }
  }
  if (task.needsHuman) {
    log('task ' + task.id + ' needs the owner: ' + task.title)
    return { stopped: 'needs-human', reason: 'task-needs-human', task: task, done: done }
  }
  const partial = a.partialSpike && Array.isArray(a.partialSpike.tasks) && a.partialSpike.tasks.map(Number).indexOf(n) >= 0 ? a.partialSpike : null
  const spikeNote = partial
    ? '\n\nPARTIAL SPIKE EVIDENCE (the full spike did NOT pass): ' + partial.note + ' Read these first: ' + partial.files.join(', ') +
      '. Do not guess unproven behaviour; stub it explicitly and say so in the summary.'
    : ''
  if (partial) {
    log('task ' + task.id + ' proceeding on PARTIAL spike evidence only (the full spike did not pass)')
  }
  if (task.dependsOnSpike && !partial) {
    const spike = await agent(
      'Check whether the file docs/superpowers/spike-results.md exists in ' + repo + ' and is non-empty. Modify nothing.',
      { label: 'spike results?', phase: 'Implement', schema: EXISTS_SCHEMA, effort: 'low' }
    )
    if (!spike || !spike.exists) {
      log('task ' + task.id + ' depends on spike results that do not exist yet')
      return { stopped: 'needs-human', reason: 'spike-results-needed', task: task, done: done }
    }
  }

  await board('Implement', 'board start ' + task.id, 'task ' + task.id + ' started', task.title)

  const impl = await agent(
    'Implement ONE plan task in the git repo ' + repo + ' on branch ' + branch + ' (switch to it if needed). ' +
      'Follow TDD: write the failing test, see it fail, write minimal code, see it pass, refactor. Happy path, failure and edge cases. ' +
      'Run gofmt, go vet and the tests before committing. Commit once with a clear message ending with the line: ' + ATTRIBUTION + ' ' +
      'Never push. Touch only what the task needs. ' + NO_SECRETS + ' Return the commit SHA, whether tests passed, and a 2-sentence summary.\n\nTASK ' +
      task.id + ': ' + task.title + '\n' + task.text + spikeNote,
    { label: 'implement ' + task.id, phase: 'Implement', schema: IMPL_SCHEMA }
  )
  if (!impl || !impl.testsPassed) {
    return { stopped: 'implement-failed', task: task, result: impl, done: done }
  }

  // ---- 4 Review + 5 Fix loop (max 3 fix rounds) ----
  let verdict = 'fail'
  let findings = []
  for (let round = 0; round <= 3; round++) {
    const reviews = await parallel([
      () =>
        agent(
          'You are a fresh reviewer. In ' + repo + ' on branch ' + branch + ', review the latest commit for plan task ' + task.id +
            ' (' + task.title + ') against the task text and the spec ' + a.specPath + '. Lens: correctness and spec compliance, ' +
            'missing tests, edge cases, interface mismatches with neighbouring tasks. Be adversarial; default to fail if unsure. ' +
            (partial ? 'Items listed as deferred in this note are NOT defects: ' + partial.note + ' ' : '') +
            'Modify nothing. Return verdict and concrete findings with file:line.\n\nTASK TEXT:\n' + task.text,
          { label: 'review correctness ' + task.id + ' r' + round, phase: 'Review', schema: REVIEW_SCHEMA }
        ),
      () =>
        agent(
          'You are a fresh security reviewer. In ' + repo + ' on branch ' + branch + ', review the latest commit for plan task ' + task.id +
            ' (' + task.title + '). Lens: secrets and tokens must never appear in logs, errors, test fixtures or committed files; ' +
            'credential and token files must be 0600; atomic writes; no path traversal; auth checks on every endpoint. ' +
            'Be adversarial; default to fail if unsure. Modify nothing. Return verdict and findings with file:line.',
          { label: 'review security ' + task.id + ' r' + round, phase: 'Review', schema: REVIEW_SCHEMA }
        ),
    ])
    const got = reviews.filter(Boolean)
    if (got.length < 2) {
      log('a reviewer for task ' + task.id + ' died; treating as fail')
    }
    findings = got.flatMap(function (r) { return r.findings })
    verdict = got.length === 2 && got.every(function (r) { return r.verdict === 'pass' }) ? 'pass' : 'fail'
    await board('Review', 'board review ' + task.id, 'task ' + task.id + ' review round ' + round, 'verdict ' + verdict + ', ' + findings.length + ' findings')
    if (verdict === 'pass') break
    if (round === 3) break
    phase('Fix')
    const fix = await agent(
      'Fix review findings for plan task ' + task.id + ' (' + task.title + ') in ' + repo + ' on branch ' + branch + '. ' +
        'Address every finding with a test first where it is a behaviour bug. Run gofmt, go vet, tests. Commit with a message ending ' +
        'with the line: ' + ATTRIBUTION + ' Never push. ' + NO_SECRETS + ' Return the new commit SHA, whether tests passed, and a summary.\n\nFINDINGS:\n- ' +
        findings.join('\n- '),
      { label: 'fix ' + task.id + ' r' + (round + 1), phase: 'Fix', schema: IMPL_SCHEMA }
    )
    if (!fix || !fix.testsPassed) {
      return { stopped: 'fix-failed', task: task, findings: findings, done: done }
    }
    impl.sha = fix.sha
  }
  if (verdict !== 'pass') {
    return { stopped: 'review-failed', task: task, findings: findings, done: done }
  }
  done.push({ id: task.id, title: task.title, sha: impl.sha })
  log('task ' + task.id + ' reviewed and passed at ' + impl.sha)
}

// ---- 6 Gate ----
phase('Gate')
const gate = await agent(
  'Run the merge gate in ' + repo + ' on branch ' + branch + ' and report real exit codes, not guesses: ' +
    '1) gofmt -l . (must list nothing); 2) go vet ./...; 3) go test ./... (add -race only if it works on this OS); ' +
    '4) cross-build for cmd/server and cmd/agent with GOOS=linux and GOOS=windows (go build -o to a temp dir, not the repo); ' +
    '5) the crew verify gate if available (/crew:verify or the verify-gate script) and quote its verdict. ' +
    'Skip a command only if its target does not exist yet, and say so in its summary. Modify no tracked files. ' +
    'Return passed=true only if every command that ran exited 0.',
  { label: 'run gate', phase: 'Gate', schema: GATE_SCHEMA }
)
if (!gate) {
  return { stopped: 'gate-failed', reason: 'gate agent died', done: done }
}
await board('Gate', 'board gate', 'gate ' + (gate.passed ? 'passed' : 'failed'), gate.commands.length + ' commands run')
if (!gate.passed) {
  return { stopped: 'gate-failed', gate: gate, done: done }
}

const whole = await agent(
  'You are a fresh, hostile reviewer of the WHOLE branch ' + branch + ' in ' + repo + ' versus its base (main). Read the spec ' + a.specPath +
    ' and plan ' + a.planPath + '. Check spec coverage, interface consistency across tasks, swap safety (backups, rollback, ' +
    'no token or email in logs, files 0600), and anything the task-level reviews could not see. Modify nothing. Default to fail if unsure.',
  { label: 'whole-branch review', phase: 'Gate', schema: REVIEW_SCHEMA, effort: 'high' }
)
if (!whole || whole.verdict !== 'pass') {
  return { stopped: 'review-failed', task: 'whole-branch', findings: whole ? whole.findings : ['reviewer died'], done: done }
}

// ---- 7 Land ----
phase('Land')
const summary = await agent(
  'Prepare a landing summary for branch ' + branch + ' in ' + repo + '. Do NOT push, merge, rebase or open a PR. ' +
    'Collect: the branch name, the commit SHAs on the branch since main, git diff --stat against main, a 3-line evidence summary of ' +
    'this gate result: ' + JSON.stringify(gate) + ', and open risks from the spec ' + a.specPath + ' that are still unverified. ' + NO_SECRETS,
  { label: 'landing summary', phase: 'Land', schema: LAND_SCHEMA, effort: 'low' }
)
await board('Land', 'board ready', 'ready to land (not merged)', 'branch ' + branch + ', gate passed, awaiting owner approval to push/merge')
return { stopped: 'ready-to-land', summary: summary, done: done, instruction: 'main asks the owner via AskUserQuestion before any push or merge' }
