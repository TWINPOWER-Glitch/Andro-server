import 'dotenv/config';
import { app } from './index.js';
import { pool } from './store.js';

const port = Number(process.env.PORT || 8787);
const server = app.listen(port, () => console.log(`Andro server listening on :${port}`));
async function shutdown() { server.close(); await pool.end(); }
process.on('SIGTERM', () => { void shutdown(); });
process.on('SIGINT', () => { void shutdown(); });