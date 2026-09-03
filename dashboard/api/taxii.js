const crypto = require('crypto');
const { Pool } = require('pg');

let _pool;
function pool() {
  if (!_pool) _pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3 });
  return _pool;
}

const COLLECTION_ID = 'cti-monitor-iocs';
const DEFAULT_LIMIT = 200;
const MAX_LIMIT = 1000;

function deterministicUUID(input) {
  const hash = crypto.createHash('sha256').update(input).digest('hex');
  return [hash.slice(0, 8), hash.slice(8, 12), '4' + hash.slice(13, 16), hash.slice(16, 20), hash.slice(20, 32)].join('-');
}

function setTaxiiHeaders(res) {
  res.setHeader('Content-Type', 'application/taxii+json;version=2.1');
}

function checkAuth(req, res) {
  const key = process.env.TAXII_API_KEY;
  if (!key) return true;
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ') || auth.slice(7) !== key) {
    res.status(401).json({ title: 'Unauthorized', http_status: 401, description: 'Valid Bearer token required' });
    return false;
  }
  return true;
}

async function handleDiscovery(res) {
  res.setHeader('Cache-Control', 's-maxage=3600, stale-while-revalidate=7200');
  return res.json({
    title: 'CTI Monitor TAXII Server',
    description: 'STIX 2.1 IOC feed extracted from OSINT threat intelligence blogs',
    contact: 'aveek063@gmail.com',
    default: '/api/taxii',
    api_roots: ['/api/taxii'],
  });
}

async function handleCollections(res) {
  res.setHeader('Cache-Control', 's-maxage=3600, stale-while-revalidate=7200');
  return res.json({
    collections: [
      {
        id: COLLECTION_ID,
        title: 'CTI Monitor IOC Feed',
        description: 'STIX 2.1 indicators and threat actors extracted from OSINT threat intelligence blogs',
        can_read: true,
        can_write: false,
        media_types: ['application/stix+json;version=2.1'],
      },
    ],
  });
}

async function handleCollectionInfo(id, res) {
  if (id !== COLLECTION_ID) {
    return res.status(404).json({ title: 'Not Found', http_status: 404, description: `Collection '${id}' not found` });
  }
  res.setHeader('Cache-Control', 's-maxage=3600, stale-while-revalidate=7200');
  return res.json({
    id: COLLECTION_ID,
    title: 'CTI Monitor IOC Feed',
    description: 'STIX 2.1 indicators and threat actors extracted from OSINT threat intelligence blogs',
    can_read: true,
    can_write: false,
    media_types: ['application/stix+json;version=2.1'],
  });
}

async function handleObjects(req, res) {
  const addedAfter = req.query.added_after || null;
  const limit = Math.min(parseInt(req.query.limit, 10) || DEFAULT_LIMIT, MAX_LIMIT);
  const page = Math.max(parseInt(req.query.page, 10) || 0, 0);
  const offset = page * limit;

  let addedAfterTs = null;
  if (addedAfter) {
    addedAfterTs = new Date(addedAfter);
    if (isNaN(addedAfterTs.getTime())) {
      return res.status(400).json({ title: 'Bad Request', http_status: 400, description: 'Invalid added_after timestamp' });
    }
  }

  const db = pool();

  const [indRows, totalRows, aptRows] = await Promise.all([
    db.query(
      `SELECT stix_object, updated_at
       FROM ioc_indicators
       WHERE stix_object IS NOT NULL
         AND ($1::timestamptz IS NULL OR updated_at >= $1)
       ORDER BY updated_at DESC
       LIMIT $2 OFFSET $3`,
      [addedAfterTs, limit, offset]
    ),
    db.query(
      `SELECT COUNT(*) AS cnt
       FROM ioc_indicators
       WHERE stix_object IS NOT NULL
         AND ($1::timestamptz IS NULL OR updated_at >= $1)`,
      [addedAfterTs]
    ),
    page === 0
      ? db.query(
          `SELECT DISTINCT attributed_apt FROM ioc_indicators
           WHERE attributed_apt IS NOT NULL AND attributed_apt != ''`
        )
      : { rows: [] },
  ]);

  const total = parseInt(totalRows.rows[0].cnt, 10);
  const more = offset + indRows.rows.length < total;

  const now = new Date().toISOString();
  const threatActors = aptRows.rows.map(({ attributed_apt }) => ({
    type: 'threat-actor',
    spec_version: '2.1',
    id: `threat-actor--${deterministicUUID(attributed_apt)}`,
    created: '2020-01-01T00:00:00Z',
    modified: now,
    name: attributed_apt,
    threat_actor_types: ['unknown'],
  }));

  const indicators = indRows.rows.map((r) => r.stix_object);
  const objects = [...threatActors, ...indicators];

  res.setHeader('Cache-Control', 's-maxage=300, stale-while-revalidate=600');
  return res.json({
    more,
    next: more ? String(page + 1) : null,
    objects,
  });
}

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ title: 'Method Not Allowed', http_status: 405 });
  }

  if (!checkAuth(req, res)) return;
  setTaxiiHeaders(res);

  // Parse the sub-path after /api/taxii (Vercel passes the full URL in req.url)
  const raw = (req.url || '').split('?')[0];
  const sub = raw.replace(/^\/api\/taxii\/?/, '').replace(/\/$/, '');

  try {
    if (sub === '' || sub === 'discovery') return await handleDiscovery(res);
    if (sub === 'collections') return await handleCollections(res);
    const colMatch = sub.match(/^collections\/([^/]+)$/);
    if (colMatch) return await handleCollectionInfo(colMatch[1], res);
    const objMatch = sub.match(/^collections\/([^/]+)\/objects$/);
    if (objMatch) {
      if (objMatch[1] !== COLLECTION_ID) {
        return res.status(404).json({ title: 'Not Found', http_status: 404, description: `Collection '${objMatch[1]}' not found` });
      }
      return await handleObjects(req, res);
    }
    return res.status(404).json({ title: 'Not Found', http_status: 404, description: `Unknown TAXII path: /${sub}` });
  } catch (err) {
    console.error('[taxii] error:', err);
    return res.status(500).json({ title: 'Internal Server Error', http_status: 500 });
  }
};
