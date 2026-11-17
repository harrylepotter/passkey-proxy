import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Explicit opt-in command: expose the agent listener, never the owner or CDP.
const gateway = `http://127.0.0.1:${Number(process.env.GATEWAY_PORT || 4780)}`;
const agentOrigin = `http://127.0.0.1:${Number(process.env.AGENT_PORT || 4782)}`;
const ownerToken = readFileSync(resolve(process.env.DATA_DIR || '.data', 'owner-token'), 'utf8').trim();
const health = await (await fetch(`${agentOrigin}/health`, { signal: AbortSignal.timeout(5000) })).json();
if (health.service !== 'agent-handoff') throw new Error('The agent-only endpoint is not running. Start the updated gateway first.');
const configure = async origin => {
  const response = await fetch(`${gateway}/api/owner/agent-origin`, { method: 'POST', signal: AbortSignal.timeout(5000), headers: { Authorization: `Bearer ${ownerToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ origin }) });
  if (!response.ok) throw new Error('The local owner gateway rejected the remote URL configuration.');
};

const endpointArgs = [];
if (process.env.NGROK_URL) {
  const url = new URL(process.env.NGROK_URL);
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('NGROK_URL must be a public HTTPS origin.');
  endpointArgs.push('--url', url.origin);
}
const child = spawn(process.env.NGROK_PATH || 'ngrok', ['http', agentOrigin, ...endpointArgs, '--inspect=false', '--log=stdout', '--log-format=json'], { stdio: ['ignore', 'pipe', 'pipe'] });
let configured = false, configuring = false, stopping = false, ngrokError = '';
const timeout = setTimeout(() => { console.error('The HTTPS tunnel did not become ready. Check the local ngrok configuration.'); void stop(1); }, 30000);
async function stop(code = 0) {
  if (stopping) return; stopping = true; clearTimeout(timeout);
  child.kill('SIGTERM');
  if (configured) await configure('').catch(() => {});
  process.exitCode = code;
}
function consume(stream) {
  let pending = '';
  stream.on('data', data => {
    pending += data.toString();
    const lines = pending.split('\n'); pending = lines.pop();
    for (const line of lines) {
      // Never echo raw tunnel logs, headers, bodies, config or credentials.
      ngrokError ||= /ERR_NGROK_\d+/.exec(line)?.[0] || '';
      let event; try { event = JSON.parse(line); } catch { continue; }
      if (configured || configuring || stopping || event.msg !== 'started tunnel' || !event.url?.startsWith('https://')) continue;
      configuring = true;
      configure(new URL(event.url).origin).then(async () => {
        if (stopping) { await configure('').catch(() => {}); return; }
        configured = true; clearTimeout(timeout);
        console.log(`Remote agent gateway ready: ${new URL(event.url).origin}`);
        console.log('Create a persistent agent link in the owner dashboard and copy its instructions to your agent.');
        console.log('Use this same ngrok hostname after restarts so saved agent links remain reachable (set NGROK_URL to your assigned domain).');
        console.log('Only agent routes are exposed. Request inspection is disabled. Keep this process running; Ctrl+C closes the tunnel.');
      }, () => { console.error('Could not configure the public agent URL.'); void stop(1); });
    }
  });
}
consume(child.stdout); consume(child.stderr);
child.on('error', () => { console.error('Could not start ngrok. Check that it is installed and configured.'); void stop(1); });
child.on('exit', () => {
  if (!stopping) { console.error(configured ? 'Agent tunnel closed.' : `Agent tunnel failed${ngrokError ? ` (${ngrokError})` : ''}. Check the ngrok configuration.`); void stop(configured ? 0 : 1); }
});
process.on('SIGINT', () => { void stop(); });
process.on('SIGTERM', () => { void stop(); });
