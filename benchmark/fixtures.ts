import {readExpected} from './expected';
import { mkdirSync, writeFileSync, existsSync, rmSync, readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { assertBenchmarkMode } from './guard';
import type { ExpectedFinding } from './score';
export const negativeHoldoutTargets=['clean-holdout-cache','clean-holdout-frame','clean-holdout-cms'] as const;
export const localTargets = ['seeded', 'clean-marketing', 'clean-docs', 'clean-portal',...negativeHoldoutTargets] as const;
const token = (label: string, length: number) => createHash('sha512').update('PUBLIC-FAKE-AEGIS-BENCHMARK-ONLY:' + label).digest('hex').slice(0, length);
export function fakeCredentials() { const jwt = (ref: string) => Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url') + '.' + Buffer.from(JSON.stringify({ role: 'service_role', ref, iss: 'benchmark-fixture', exp: 1 })).toString('base64url') + '.' + Buffer.from('FAKE-NOT-A-SIGNATURE').toString('base64url'); return { stripe: 'sk_live_' + token('stripe', 24), openai: 'sk-proj-' + token('openai', 48), awsId: 'AKIA' + token('aws-id', 16).toUpperCase(), awsSecret: token('aws-secret', 40), supabase: jwt('fake-source'), bundle: jwt('fake-bundle'), history: 'sk_live_' + token('deleted-history', 24) }; }
export function fixtureDefinition(name: string) {
    if (!localTargets.includes(name as typeof localTargets[number]))
        throw new Error('Unknown local fixture');
    const files: Record<string, string> = {
        'package.json': JSON.stringify({ name: 'aegis-benchmark-' + name, private: true, dependencies: { next: '16.4.5', react: '19.2.0', 'react-dom': '19.2.0' } }, null, 2) + '\n',
        'app/layout.tsx': 'export default function Layout({children}:{children:React.ReactNode}) { return <html lang="en"><body>{children}</body></html> }\n',
        'app/page.tsx': 'export default function Page(){ return <main><h1>Benchmark fixture</h1><p>Static public content.</p></main> }\n',
        'README.md': 'BENCHMARK ONLY. Synthetic Next.js-shaped fixture. No real credentials, no remote, no install/build/run of fixture code.\n'
    };
    if((negativeHoldoutTargets as readonly string[]).includes(name)){const fixture=JSON.parse(readFileSync(new URL('./negative-holdout/'+name+'.json',import.meta.url),'utf8'));Object.assign(files,fixture.files);}
    const expected: ExpectedFinding[] = [];
    const add = (id: string, category: ExpectedFinding['category'], file: string, content: string, severity = 'high', line = 1) => { files[file] = content; expected.push({ id, category, location: file + ':' + line, severity }); };
    if (name === 'seeded') {
        const f = fakeCredentials();
        add('stripe-file', 'secret', 'src/stripe.ts', 'export const stripeKey = ' + JSON.stringify(f.stripe) + ';\n');
        add('openai-file', 'secret', 'src/openai.ts', 'export const openaiKey = ' + JSON.stringify(f.openai) + ';\n');
        add('aws-pair', 'secret', 'src/aws.ts', 'export const accessKeyId = ' + JSON.stringify(f.awsId) + ';\nexport const secretAccessKey = ' + JSON.stringify(f.awsSecret) + ';\n');
        add('supabase-service-role', 'secret', 'src/supabase.ts', 'export const serviceKey = ' + JSON.stringify(f.supabase) + ';\n');
        add('frontend-bundle-secret', 'secret', 'public/_next/static/chunks/bundle.js', 'globalThis.fakeBundleCredential=' + JSON.stringify(f.bundle) + ';\n');
        add('next-public-misuse', 'secret', 'src/public-config.ts', 'export const NEXT_PUBLIC_DATABASE_PASSWORD="FAKE-BENCHMARK-PASSWORD-NOT-A-REAL-ACCOUNT";\n');
        expected.push({ id: 'deleted-history-secret', category: 'secret', location: 'src/deleted-secret.ts:1', severity: 'high' });
        add('eval-input', 'code', 'src/eval.ts', 'export function evaluate(input:string){ return eval(input); }\n', 'medium');
        add('sql-concat', 'code', 'src/query.ts', 'export function query(db:any,id:string){ return db.query(`SELECT * FROM private_items WHERE id = \'${id}\'`); }\n');
        add('shell-input', 'code', 'src/shell.ts', 'import {exec} from "node:child_process"; export function command(input:string){ exec("cat "+input); }\n');
        add('html-input', 'code', 'app/unsafe/page.tsx', 'export default function Page({text}:{text:string}){ return <div dangerouslySetInnerHTML={{__html:text}}/> }\n', 'medium');
        add('tls-disabled', 'config', 'src/tls.ts', 'export const transport={rejectUnauthorized:false};\n');
        add('missing-rls', 'config', 'supabase/migrations/001_table.sql', 'CREATE TABLE public.private_records(id uuid, owner_id uuid);\n');
        add('public-read-policy', 'config', 'supabase/migrations/002_read.sql', 'CREATE POLICY wide_read ON public.private_records FOR SELECT TO anon USING (true);\n', 'medium');
        add('public-write-policy', 'config', 'supabase/migrations/003_write.sql', 'CREATE POLICY wide_insert ON public.private_records FOR INSERT TO anon WITH CHECK (true);\n');
        add('edge-jwt-disabled', 'config', 'supabase/config.toml', '[functions.private-records]\nverify_jwt = false\n', 'high', 2);
        add('no-auth-route', 'api', 'app/api/private/route.ts', 'export async function GET(){ return Response.json({privateRecord:"fixture-only"}); }\n');
        add('idor-route', 'api', 'app/api/records/[id]/route.ts', 'export async function GET(req:Request,{params}:{params:Promise<{id:string}>}){ const {id}=await params; const records:Record<string,{owner_id:string,privateNote:string}>={fixture:{owner_id:"another-fixture-user",privateNote:"FAKE-private-data"}}; return Response.json(records[id]); }\n');
        add('jwt-none', 'api', 'src/jwt.ts', 'import jwt from "jsonwebtoken"; export function verify(t:string,k:string){ return jwt.verify(t,k,{algorithms:["none"]}); }\n');
        add('cors-reflection', 'api', 'src/cors.ts', 'import cors from "cors"; export const handler=cors({origin:true,credentials:true});\n');
        files['package-lock.json'] = JSON.stringify({ name: 'fixture', lockfileVersion: 3, packages: { '': { name: 'fixture' }, 'node_modules/lodash': { version: '4.17.20', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz' } } }, null, 2) + '\n';
        const lockLine = files['package-lock.json'].split('\n').findIndex(l => l.includes('"node_modules/lodash"')) + 1;
        expected.push({ id: 'lodash-known-advisory', category: 'dependency', location: 'package-lock.json:' + lockLine, severity: 'high' });
    }
    if (name === 'clean-docs')
        files['src/checksum.ts'] = 'import {createHash} from "node:crypto"; export function nonSecurityChecksum(text:string){ return createHash("md5").update(text).digest("hex"); }\n';
    if (name === 'clean-portal')
        files['app/help/page.tsx'] = 'const trustedStaticHtml="<p>Help text authored in source; no user content.</p>";\nexport default function Page(){ return <div dangerouslySetInnerHTML={{__html:trustedStaticHtml}}/> }\n';
    return { files, expected };
}
export function prepareFixture(base: string, name: string,phase:'dev'|'final'='final') {
    assertBenchmarkMode();
    if(phase!=='final'&&(negativeHoldoutTargets as readonly string[]).includes(name))throw new Error('Negative holdout requires --final');
    const { files, expected } = fixtureDefinition(name);
    if(phase==='dev'&&name==='seeded')for(const f of readExpected(name).findings.filter(f=>f.split==='holdout'))delete files[f.location.replace(/:\d+$/,'')];
    const root = resolve(base, name), marker = join(root, '.benchmark-fixture');
    if (existsSync(root)) {
        if (!existsSync(marker))
            throw new Error('Refusing to replace a directory without benchmark marker');
        rmSync(root, { recursive: true, force: true });
    }
    mkdirSync(root, { recursive: true });
    writeFileSync(marker, 'owned by Aegis benchmark generator\n');
    for (const [file, text] of Object.entries(files)) {
        const dest = join(root, file);
        mkdirSync(resolve(dest, '..'), { recursive: true });
        writeFileSync(dest, text);
    }
    if (name === 'seeded'&&phase==='final') {
        const git = (...args: string[]) => execFileSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', '-c', 'user.name=Aegis Benchmark', '-c', 'user.email=benchmark@example.invalid', ...args], { cwd: root, stdio: 'pipe', env: { ...process.env, GIT_LFS_SKIP_SMUDGE: '1', GIT_TERMINAL_PROMPT: '0', GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z' } });
        git('init', '--initial-branch=main');
        writeFileSync(join(root, 'src/deleted-secret.ts'), 'export const deletedKey = ' + JSON.stringify(fakeCredentials().history) + ';\n');
        git('add', '--all');
        git('commit', '-m', 'benchmark fake fixtures with deleted secret');
        git('rm', 'src/deleted-secret.ts');
        git('commit', '-m', 'delete fake secret from working tree');
    }
    return { root, expected };
}
