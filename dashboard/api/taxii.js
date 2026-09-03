const { dispatch } = require('./taxii/[...segments]');

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ title: 'Method Not Allowed', http_status: 405 });
  }
  return dispatch(req, res, []);
};
