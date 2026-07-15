import assert from 'node:assert';
import { entryHost, entryMime, matchChip, filterEntries } from '../web/ui/filter.js';

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
// pas de crash sur entrée sans url/headers
assert.equal(filterEntries([{}], [{field:'url',op:'contains',value:'x',exclude:false}]).length, 0);
console.log('filter_test OK');
