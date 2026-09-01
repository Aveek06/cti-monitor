const URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/500/';

module.exports = async function handler(req, res) {
  const apiKey = process.env.URLHAUS_API_KEY;
  if (!apiKey) {
    return res.status(503).json({ error: 'URLHAUS_API_KEY not configured on server.' });
  }

  try {
    const upstream = await fetch(URLHAUS_API, {
      method: 'POST',
      headers: { 'Auth-Key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    if (!upstream.ok) {
      return res.status(502).json({ error: `URLhaus returned HTTP ${upstream.status}` });
    }

    const data = await upstream.json();
    if (data.query_status !== 'ok') {
      return res.status(502).json({ error: data.query_status });
    }

    const all = data.urls || [];
    const online = all.filter(u => u.url_status === 'online');

    // 5-minute CDN cache — prevents hammering URLhaus on rapid refreshes
    res.setHeader('Cache-Control', 'public, s-maxage=300, stale-while-revalidate=60');
    return res.json({
      total: all.length,
      online: online.length,
      fetched_at: new Date().toISOString(),
      urls: online.map(u => ({
        url:        u.url || '',
        threat:     u.threat || '',
        tags:       Array.isArray(u.tags) ? u.tags : u.tags ? [u.tags] : [],
        date_added: (u.date_added || '').slice(0, 10),
      })),
    });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
};
