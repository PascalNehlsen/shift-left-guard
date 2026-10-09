import { describe, expect, test } from 'claude-code/testing'

import { applyEdit, classify, destructive, formatFindings, introduced, scan } from '../hooks/rules'

const ids = (path: string, text: string) => scan(path, text).map(f => f.id)

describe('classify', () => {
  test('knows the file kinds', async () => {
    expect(classify('/r/.github/workflows/ci.yml', '')).toBe('workflow')
    expect(classify('/r/Dockerfile', '')).toBe('dockerfile')
    expect(classify('/r/docker/Dockerfile.prod', '')).toBe('dockerfile')
    expect(classify('/r/infra/main.tf', '')).toBe('terraform')
    expect(classify('/r/k8s/deploy.yaml', 'apiVersion: apps/v1\nkind: Deployment\n')).toBe('kubernetes')
    expect(classify('/r/docker-compose.yml', 'services:\n')).toBe('other')
  })
})

describe('workflows', () => {
  const path = '/r/.github/workflows/ci.yml'

  test('flags unpinned actions, not SHA-pinned or local ones', async () => {
    const text = [
      'permissions: { contents: read }',
      'jobs:',
      '  b:',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '      - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af # v4.1.0',
      '      - uses: ./.github/actions/local',
    ].join('\n')
    expect(ids(path, text)).toEqual(['GHA001'])
  })

  test('flags script injection inside run blocks only', async () => {
    const text = [
      'permissions: { contents: read }',
      'jobs:',
      '  b:',
      '    if: ${{ github.event.pull_request.title != "" }}',
      '    steps:',
      '      - run: |',
      '          echo "${{ github.event.pull_request.title }}"',
      '      - env:',
      '          TITLE: ${{ github.event.issue.title }}',
      '        run: echo "$TITLE"',
    ].join('\n')
    expect(ids(path, text)).toEqual(['GHA003'])
  })

  test('flags pull_request_target with PR head checkout as critical', async () => {
    const text = [
      'on: pull_request_target',
      'permissions: write-all',
      'jobs:',
      '  b:',
      '    steps:',
      '      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683',
      '        with:',
      '          ref: ${{ github.event.pull_request.head.sha }}',
    ].join('\n')
    const found = scan(path, text)
    expect(found.map(f => f.id)).toEqual(['GHA002', 'GHA004'])
    expect(found[0]?.severity).toBe('critical')
  })

  test('honours guard:ignore', async () => {
    const text = 'permissions: {}\njobs:\n  b:\n    steps:\n      # guard:ignore GHA001 internal action\n      - uses: org/x@main'
    expect(ids(path, text)).toEqual([])
  })
})

describe('Dockerfile', () => {
  test('flags latest, root, baked secrets, curl|sh', async () => {
    const text = [
      'FROM python:latest AS build',
      'ENV API_KEY=abc123',
      'RUN curl -fsSL https://x.sh | bash',
      'FROM build',
      'CMD ["python"]',
    ].join('\n')
    expect(ids('/r/Dockerfile', text).sort()).toEqual(['DKR001', 'DKR002', 'DKR003', 'DKR005'])
  })

  test('passes a hardened Dockerfile', async () => {
    const text = [
      'FROM python:3.13-slim AS build',
      'ARG API_KEY',
      'COPY . /app',
      'FROM build',
      'USER 10001',
      'CMD ["python"]',
    ].join('\n')
    expect(ids('/r/Dockerfile', text)).toEqual([])
  })
})

describe('Terraform across clouds', () => {
  test('GCP, AWS and Azure misconfigurations', async () => {
    const text = [
      'resource "google_storage_bucket_iam_member" "p" { member = "allUsers" }',
      'resource "google_project_iam_member" "o" { role = "roles/owner" }',
      'source_ranges = ["0.0.0.0/0"]',
      'publicly_accessible = true',
      'password = "hunter2hunter2"',
      'acl = "public-read"',
      'role_definition_name = "Owner"',
      'storage_encrypted = false',
      'password = var.db_password',
      'resource "google_cloud_run_v2_service_iam_member" "public" {',
      '  role   = "roles/run.invoker"',
      '  member = "allUsers"',
      '}',
    ].join('\n')
    expect(ids('/r/main.tf', text).sort()).toEqual(['TF001', 'TF002', 'TF002', 'TF003', 'TF003', 'TF004', 'TF005', 'TF006'])
  })
})

describe('Kubernetes', () => {
  test('flags privileged pods and latest images', async () => {
    const text = [
      'apiVersion: v1',
      'kind: Pod',
      'spec:',
      '  hostNetwork: true',
      '  containers:',
      '    - image: nginx',
      '      securityContext:',
      '        privileged: true',
    ].join('\n')
    expect(ids('/r/pod.yaml', text).sort()).toEqual(['K8S001', 'K8S002', 'K8S004'])
  })
})

describe('secrets', () => {
  test('finds real-looking keys anywhere, skips documented examples', async () => {
    expect(ids('/r/app/settings.py', `KEY = "AKIA${'Q'.repeat(16)}"`)).toEqual(['SEC002'])
    expect(ids('/r/README.md', 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE')).toEqual([])
    // guard:ignore SEC001 test fixture, not a key
    expect(ids('/r/id', '-----BEGIN OPENSSH PRIVATE KEY-----')).toEqual(['SEC001'])
  })
})

describe('diffing and edits', () => {
  test('only reports what an edit introduces', async () => {
    const path = '/r/Dockerfile'
    const before = 'FROM node:latest\nCMD ["node"]'
    const after = applyEdit(before, 'CMD', 'ENV DB_PASSWORD=x\nCMD')
    expect(after).toBeDefined()
    expect(introduced(scan(path, before), scan(path, after ?? '')).map(f => f.id)).toEqual(['DKR003'])
  })

  test('applyEdit mirrors the tool', async () => {
    expect(applyEdit('a a', 'a', 'b')).toBe('b a')
    expect(applyEdit('a a', 'a', 'b', true)).toBe('b b')
    expect(applyEdit('a', 'z', 'b')).toBeUndefined()
  })
})

describe('cloud commands', () => {
  test('spots destructive commands and production targets', async () => {
    expect(destructive('terraform destroy -var-file=prod.tfvars')).toEqual({
      reason: 'Terraform change without a reviewed plan',
      isProd: true,
    })
    expect(destructive('gcloud run services delete api --region europe-west3')?.reason).toBe('gcloud delete')
    expect(destructive('aws s3 rm s3://bucket --recursive')).toBeDefined()
    expect(destructive('az group delete -n rg-dev')).toBeDefined()
    expect(destructive('kubectl delete ns staging')).toBeDefined()
    expect(destructive('terraform plan')).toBeUndefined()
    expect(destructive('gcloud run services list')).toBeUndefined()
    expect(destructive('kubectl delete pod web-1')).toBeUndefined()
  })
})

describe('secret masking', () => {
  test('never echoes a secret back to the model', async () => {
    const key = `AKIA${'Q'.repeat(16)}`
    const shown = formatFindings('/r/a.py', scan('/r/a.py', `KEY = "${key}"`))
    expect(shown).toContain('SEC002')
    expect(shown).not.toContain(key)
    const env = formatFindings('/r/Dockerfile', scan('/r/Dockerfile', 'FROM a:1\nENV DB_PASSWORD=hunter2hunter2\nUSER app'))
    expect(env).toContain('DKR003')
    expect(env).not.toContain('hunter2hunter2')
    const tf = formatFindings('/r/main.tf', scan('/r/main.tf', 'password = "s3cr3t-value"'))
    expect(tf).not.toContain('s3cr3t-value')
  })
})
