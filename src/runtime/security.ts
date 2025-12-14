import { access, realpath, stat } from "node:fs/promises";
import path from "node:path";
import picomatch from "picomatch";
import type { AppConfig, ProjectEntry } from "./config.js";

export interface ResolvedProjectPath {
  project_id: string;
  project_name: string;
  project_path_resolved: string;
}

function toPosixPath(p: string): string {
  return p.replaceAll("\\", "/");
}

export async function validateAndResolveProjectPath(
  config: AppConfig,
  project: ProjectEntry,
  customPathCandidate: string | null,
): Promise<ResolvedProjectPath> {
  const rawPath = project.path === "*" ? (customPathCandidate ?? "") : project.path;
  if (!rawPath) throw new Error("Path is required");

  const candidate = path.isAbsolute(rawPath) ? rawPath : path.resolve(config.config_dir, rawPath);
  const resolved = await realpath(candidate);

  const st = await stat(resolved).catch(() => null);
  if (!st || !st.isDirectory()) throw new Error("Path must be an existing directory");
  await access(resolved);

  if (config.security.restrict_paths) {
    const roots = await Promise.all(config.security.allow_roots.map(async (r) => realpath(r).catch(() => null)));
    const allowed = roots
      .filter((r): r is string => typeof r === "string")
      .some((root) => resolved === root || resolved.startsWith(`${root}${path.sep}`));
    if (!allowed) {
      throw new Error("Path is not within allowed roots");
    }

    const denyMatchers = config.security.deny_globs.map((g) => picomatch(g, { dot: true }));
    const posix = toPosixPath(resolved);
    for (const m of denyMatchers) {
      if (m(posix) || m(`${posix}/`) || m(`${posix}/x`)) {
        throw new Error("Path is denied by security rules");
      }
    }
  }

  return {
    project_id: project.id,
    project_name: project.name,
    project_path_resolved: resolved,
  };
}

