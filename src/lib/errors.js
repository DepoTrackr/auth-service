const sendError = (res, status, code, message) => res.status(status).json({ error: message, code });

module.exports = { sendError };
