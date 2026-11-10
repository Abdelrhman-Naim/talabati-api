export function redact(value:string){return value
  .replace(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,'[REDACTED_PRIVATE_KEY]')
  .replace(/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s/:"'<>]+:[^\s@"'<>]+@[^\s"'<>]+/g,'[REDACTED_DATABASE_URI]')
  .replace(/\b(?:github_pat_[\w]+|xox[baprs]-[\w-]+|sk-proj-[\w-]+)\b/g,'[REDACTED_SECRET]')
  .replace(/\b(sb_secret_[\w-]+|sk_(?:live|test)_[\w-]+|gh[pousr]_[\w]+|AKIA[A-Z0-9]{16})\b/g,'[REDACTED_SECRET]')
  .replace(/\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/g,'[REDACTED_JWT]')
  .replace(/Bearer\s+[A-Za-z0-9._~+\/-]+=*/gi,'Bearer [REDACTED]')
  .replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi,'$1[REDACTED]@')
  .replace(/([?&](?:api[_-]?key|token|secret|password|access_token|session(?:id)?|csrf|nonce)=)[^&\s"'<>]*/gi,'$1[REDACTED]')
  .replace(/((?:api[_-]?key|password|secret|authorization|cookie)["']?\s*[:=]\s*["']?)[^\s"'<>;,]+/gi,'$1[REDACTED]');}
