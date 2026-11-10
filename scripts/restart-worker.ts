// Local development restart only. Existing worker detects loss of its lock and exits.
import {getStore} from '../src/lib/db';
import {setTimeout} from 'node:timers/promises';
const store=getStore();
store.db.prepare("DELETE FROM locks WHERE name='scan-worker'").run();
store.close();
await setTimeout(5500);
