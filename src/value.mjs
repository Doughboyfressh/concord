import { createHash } from 'node:crypto';

export class HarnessError extends Error {
  constructor(code, message, details = null) {
    super(message);
    this.name = 'HarnessError';
    this.code = code;
    this.details = details;
  }
}

const unsafe = new Set(['__proto__', 'prototype', 'constructor']);
const fail = (message) => { throw new HarnessError('INVALID_JSON', message); };

// A deliberately narrow JSON domain: no coercion, accessors, toJSON, or hidden state.
export function canonical(value) {
  const seen = new Set();
  function visit(v, depth) {
    if (depth > 64) fail('JSON nesting exceeds 64 levels');
    if (v === null) return 'null';
    if (typeof v === 'string' || typeof v === 'boolean') return JSON.stringify(v);
    if (typeof v === 'number') {
      if (!Number.isFinite(v) || (Number.isInteger(v) && !Number.isSafeInteger(v))) fail('Unsafe number');
      return JSON.stringify(v);
    }
    if (typeof v !== 'object') fail('Value is outside the JSON domain');
    if (seen.has(v)) fail('Cyclic JSON value');
    seen.add(v);
    let result;
    if (Array.isArray(v)) {
      if (Object.getOwnPropertySymbols(v).length || Object.keys(v).length !== v.length) fail('Sparse or decorated array');
      const values = [];
      for (let i = 0; i < v.length; i++) {
        const d = Object.getOwnPropertyDescriptor(v, String(i));
        if (!d || !('value' in d)) fail('Array accessor or hole');
        values.push(visit(d.value, depth + 1));
      }
      result = '[' + values.join(',') + ']';
    } else {
      if (![Object.prototype, null].includes(Object.getPrototypeOf(v))) fail('Non-plain JSON object');
      if (Object.getOwnPropertySymbols(v).length) fail('Symbol key');
      const parts = [];
      for (const key of Object.getOwnPropertyNames(v).sort()) {
        if (unsafe.has(key)) fail('Unsafe object key: ' + key);
        const d = Object.getOwnPropertyDescriptor(v, key);
        if (!d.enumerable || !('value' in d)) fail('Hidden property or accessor');
        parts.push(JSON.stringify(key) + ':' + visit(d.value, depth + 1));
      }
      result = '{' + parts.join(',') + '}';
    }
    seen.delete(v);
    return result;
  }
  return visit(value, 0);
}

export const digest = (value) => createHash('sha256').update(canonical(value)).digest('hex');
export const clone = (value) => JSON.parse(canonical(value));
export function parseJson(text) {
  if (typeof text !== 'string') fail('Expected JSON text');
  let i = 0;
  const ws = () => { while (/[\x20\t\r\n]/.test(text[i] ?? '') && i < text.length) i++; };
  function string() {
    const start = i++;
    while (i < text.length) {
      const c = text[i++];
      if (c === '"') {
        try { return JSON.parse(text.slice(start, i)); } catch { fail('Invalid JSON string'); }
      }
      if (c === '\\') i++;
    }
    fail('Unterminated JSON string');
  }
  function value(depth) {
    if (depth > 64) fail('JSON nesting exceeds 64 levels');
    ws();
    if (text[i] === '"') { string(); return; }
    if (text[i] === '{' || text[i] === '[') {
      const object = text[i++] === '{';
      const end = object ? '}' : ']';
      const keys = new Set();
      ws();
      if (text[i] === end) { i++; return; }
      for (;;) {
        if (object) {
          ws();
          if (text[i] !== '"') fail('Expected object key');
          const key = string();
          if (keys.has(key)) fail('Duplicate JSON key');
          keys.add(key);
          ws();
          if (text[i++] !== ':') fail('Expected colon');
        }
        value(depth + 1); ws();
        if (text[i] === end) { i++; return; }
        if (text[i++] !== ',') fail('Expected comma');
      }
    }
    const m = /^(?:null|true|false|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));
    if (!m) fail('Invalid JSON token');
    i += m[0].length;
  }
  value(0); ws();
  if (i !== text.length) fail('Trailing JSON content');
  let result;
  try { result = JSON.parse(text); } catch { fail('Invalid JSON document'); }
  canonical(result);
  return result;
}
export function deepFreeze(value) {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

const keywords = new Set(['type', 'properties', 'required', 'additionalProperties', 'items', 'enum', 'const', 'minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems', 'description', 'title', '$schema', 'anyOf', 'oneOf']);
const types = ['object', 'array', 'string', 'number', 'integer', 'boolean', 'null'];

export function validateSchema(value, schema) {
  canonical(value);
  canonical(schema);
  function checkSchema(s, depth = 0) {
    if (typeof s === 'boolean') return;
    if (!s || typeof s !== 'object' || Array.isArray(s) || depth > 32) throw new HarnessError('INVALID_SCHEMA', 'Invalid schema');
    for (const k of Object.keys(s)) if (!keywords.has(k)) throw new HarnessError('INVALID_SCHEMA', 'Unsupported schema keyword: ' + k);
    if (s.type !== undefined && !types.includes(s.type)) throw new HarnessError('INVALID_SCHEMA', 'Unsupported schema type');
    if (s.properties !== undefined) {
      if (!s.properties || typeof s.properties !== 'object' || Array.isArray(s.properties)) throw new HarnessError('INVALID_SCHEMA', 'Invalid properties');
      Object.values(s.properties).forEach(x => checkSchema(x, depth + 1));
    }
    if (s.required !== undefined && (!Array.isArray(s.required) || s.required.some(k => typeof k !== 'string') || new Set(s.required).size !== s.required.length)) throw new HarnessError('INVALID_SCHEMA', 'Invalid required fields');
    if (s.additionalProperties !== undefined) checkSchema(s.additionalProperties, depth + 1);
    if (s.items !== undefined) checkSchema(s.items, depth + 1);
    if (s.enum !== undefined && (!Array.isArray(s.enum) || !s.enum.length)) throw new HarnessError('INVALID_SCHEMA', 'Invalid enum');
    for (const k of ['minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems']) {
      if (s[k] !== undefined && (typeof s[k] !== 'number' || !Number.isFinite(s[k]) || ((k.includes('Length') || k.includes('Items')) && (!Number.isSafeInteger(s[k]) || s[k] < 0)))) throw new HarnessError('INVALID_SCHEMA', 'Invalid schema bound');
    }
    for (const k of ['oneOf', 'anyOf']) if (s[k] !== undefined) {
      if (!Array.isArray(s[k]) || !s[k].length) throw new HarnessError('INVALID_SCHEMA', 'Empty schema alternatives');
      s[k].forEach(x => checkSchema(x, depth + 1));
    }
  }
  checkSchema(schema);
  // Where a value failed and which rule it broke, so a rejection is correctable. Round 005
  // measured the cost of not having this: "Value does not satisfy the declared schema" names the
  // rule but not the field, and a model could not act on it. Deliberately records LOCATION and
  // RULE only, never any value: this text reaches model context and journaled failure reasons, so
  // it must not become a channel for the data being validated. Property names are structural, and
  // are length-capped so an oversized key cannot ride along as content.
  let failure = null;
  let speculative = 0;
  const segment = (key) => '/' + String(key).replace(/~/g, '~0').replace(/\//g, '~1').slice(0, 64);
  // A failure inside an anyOf/oneOf alternative is expected rather than diagnostic, so only
  // non-speculative failures are recorded. The first one encountered wins, and object traversal is
  // sorted by key, making the reported path a pure function of content rather than of key
  // insertion order — required, because this string is recorded in journals and must replay.
  const note = (path, rule) => { if (!speculative && !failure) failure = { path, rule }; };
  const branch = (fn) => { speculative++; try { return fn(); } finally { speculative--; } };

  function accepts(v, s, path = '') {
    if (typeof s === 'boolean') { if (!s) note(path, 'schema forbids any value here'); return s; }
    if (s.const !== undefined && canonical(v) !== canonical(s.const)) { note(path, 'does not equal the required constant'); return false; }
    if (s.enum && !s.enum.some(x => canonical(v) === canonical(x))) { note(path, 'is not one of the permitted values'); return false; }
    if (s.anyOf && !branch(() => s.anyOf.some(x => accepts(v, x, path)))) { note(path, 'matches none of the permitted alternatives'); return false; }
    if (s.oneOf && branch(() => s.oneOf.filter(x => accepts(v, x, path)).length) !== 1) { note(path, 'must match exactly one alternative'); return false; }
    const kind = v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v;
    if (s.type && !(s.type === kind || (s.type === 'integer' && kind === 'number' && Number.isSafeInteger(v)))) {
      note(path, `expected type ${s.type} but found ${kind}`); return false;
    }
    if (kind === 'object') {
      const missing = s.required?.filter(k => !Object.hasOwn(v, k)) ?? [];
      if (missing.length) { note(path, `missing required ${missing.length > 1 ? 'properties' : 'property'} ${missing.slice(0, 8).map(k => String(k).slice(0, 64)).join(', ')}`); return false; }
      for (const k of Object.keys(v).sort()) {
        const child = v[k];
        // A DECLARED property name comes from the schema, so naming it in a path reveals nothing
        // about the data. An UNDECLARED key is itself caller data — a key can be an email address
        // or a secret — so it is never echoed; the permitted names are listed instead, which is
        // both leak-free and more useful for correcting the input.
        if (s.properties && Object.hasOwn(s.properties, k)) { if (!accepts(child, s.properties[k], path + segment(k))) return false; }
        else if (s.additionalProperties !== undefined) {
          if (s.additionalProperties === false) {
            const permitted = Object.keys(s.properties ?? {}).sort().slice(0, 12).join(', ');
            note(path, `has an undeclared property; permitted ${permitted ? 'properties are ' + permitted : 'properties: none'}`);
            return false;
          }
          if (!accepts(child, s.additionalProperties, path + '/(additional property)')) return false;
        }
      }
    }
    if (kind === 'array') {
      if (s.minItems !== undefined && v.length < s.minItems) { note(path, `needs at least ${s.minItems} item${s.minItems === 1 ? '' : 's'} but has ${v.length}`); return false; }
      if (s.maxItems !== undefined && v.length > s.maxItems) { note(path, `allows at most ${s.maxItems} items but has ${v.length}`); return false; }
      if (s.items !== undefined) for (let i = 0; i < v.length; i++) if (!accepts(v[i], s.items, path + segment(i))) return false;
    }
    if (kind === 'string') {
      if (s.minLength !== undefined && [...v].length < s.minLength) { note(path, `is shorter than the minimum length ${s.minLength}`); return false; }
      if (s.maxLength !== undefined && [...v].length > s.maxLength) { note(path, `is longer than the maximum length ${s.maxLength}`); return false; }
    }
    if (kind === 'number') {
      if (s.minimum !== undefined && v < s.minimum) { note(path, `is below the minimum ${s.minimum}`); return false; }
      if (s.maximum !== undefined && v > s.maximum) { note(path, `is above the maximum ${s.maximum}`); return false; }
    }
    return true;
  }
  if (!accepts(value, schema)) {
    const where = failure ? `${failure.path === '' ? 'the value' : failure.path} ${failure.rule}` : null;
    throw new HarnessError('SCHEMA_MISMATCH', where ? `Value does not satisfy the declared schema: ${where}` : 'Value does not satisfy the declared schema');
  }
  return true;
}
