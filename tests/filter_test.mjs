import assert from 'node:assert';
import { entryHost, entryMime, matchChip, filterEntries, dedupEntries, networkKey, consoleKey } from '../web/ui/filter.js';

const E = [
  { url: 'https://a.example.com/x.js', method:'GET', status:200, resource_type:'script', headers:{'content-type':'application/javascript; charset=utf-8'} },
  { url: 'https://cdn.other.net/p.png', method:'GET', status:200, resource_type:'image', headers:{'Content-Type':'image/png'} },
  { url: 'https://a.example.com/api', method:'POST', status:404, resource_type:'xhr', headers:{} },
];
assert.equal(entryHost(E[0].url), 'a.example.com');
assert.equal(entryHost('not a url'), '');
assert.equal(entryMime(E[0]).startsWith('application/javascript'), true);
assert.equal(entryMime(E[2]), 'xhr'); // fallback resource_type
// include: domain contains example -> 2
assert.equal(filterEntries(E, [{field:'domain',op:'contains',value:'example',exclude:false}]).length, 2);
// exclude: type equals image -> 2
assert.equal(filterEntries(E, [{field:'type',op:'equals',value:'image',exclude:true}]).length, 2);
// cumul: domain example AND status 404 -> 1
assert.equal(filterEntries(E, [{field:'domain',op:'contains',value:'example',exclude:false},{field:'status',op:'equals',value:'404',exclude:false}]).length, 1);
// mime contains png -> 1
assert.equal(filterEntries(E, [{field:'mime',op:'contains',value:'png',exclude:false}]).length, 1);
// cumul include+exclude SIMULTANÉ : domaine contient example ET exclure status=200
// -> les 2 entrées example.com passent le include ; la 1re (status 200) est
// retirée par l'exclude, seule l'entrée /api (status 404) reste -> 1
assert.equal(filterEntries(E, [
  {field:'domain',op:'contains',value:'example',exclude:false},
  {field:'status',op:'equals',value:'200',exclude:true},
]).length, 1);
// op:'equals' utilisé en INCLUDE : type = image (égalité stricte insensible casse) -> 1
assert.equal(filterEntries(E, [{field:'type',op:'equals',value:'IMAGE',exclude:false}]).length, 1);
// pas de crash sur entrée sans url/headers
assert.equal(filterEntries([{}], [{field:'url',op:'contains',value:'x',exclude:false}]).length, 0);

// --- dédup natif réseau (method+status+type+url) ---
const D = [
  { url:'https://a/x', method:'GET', status:200, resource_type:'script' },
  { url:'https://a/x', method:'GET', status:200, resource_type:'script' },
  { url:'https://a/y', method:'GET', status:200, resource_type:'script' },
];
const dn = dedupEntries(D, networkKey);
assert.equal(dn.length, 2);            // 3 entrées -> 2 uniques
assert.equal(dn[0]._count, 2);         // la 1re fusionne 2 occurrences
assert.equal(dn[1]._count, 1);
// ordre stable : première apparition conservée
assert.equal(dn[0].url, 'https://a/x');

// --- filtre console (champs text/level) ---
const C = [
  { level:'error', text:'boom at foo' },
  { level:'warning', text:'slow' },
  { level:'error', text:'boom at foo' },
];
// dédup console : 2 uniques, la ligne error x2
const dc = dedupEntries(C, consoleKey);
assert.equal(dc.length, 2);
assert.equal(dc.find((c) => c.level === 'error')._count, 2);
// filtre par niveau (equals) et par texte (contains)
assert.equal(filterEntries(C, [{field:'level',op:'equals',value:'error',exclude:false}]).length, 2);
assert.equal(filterEntries(C, [{field:'text',op:'contains',value:'boom',exclude:false}]).length, 2);
assert.equal(filterEntries(C, [{field:'level',op:'equals',value:'error',exclude:true}]).length, 1);

console.log('filter_test OK');
