import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const DEFAULT_ADMIN_EMAIL = 'saqafaacademy66@gmail.com';
const DATA_DIR = path.resolve(__dirname, '.data');
const AUTH_STORE_FILE = path.join(DATA_DIR, 'academy-auth.json');

type PortalRole = 'teacher' | 'student' | 'parent';
type ApprovalStatus = 'Pending' | 'Approved' | 'Rejected';

interface ClaimedAdminRecord {
  email: string;
  salt: string;
  hashHex: string;
  claimedAt: string;
}

interface AdminSessionPayload {
  sub: string;
  role: 'admin';
  jti: string;
  exp: number;
}

interface PortalSessionPayload {
  uid: string;
  role: PortalRole;
  linkedProfileId: string;
  name: string;
  email: string;
  phone: string;
  jti: string;
  exp: number;
}

interface UserAccountRecord {
  id: string;
  role: PortalRole;
  linkedProfileId: string;
  name: string;
  email: string;
  phone: string;
  normalizedPhone: string;
  salt: string | null;
  hashHex: string | null;
  approvalStatus: ApprovalStatus;
  approvedAt: string | null;
  approvedBy: string | null;
  status: 'Active' | 'Suspended';
  createdAt: string;
  lastLoginAt: string | null;
  loginCount: number;
  passwordUpdatedAt: string | null;
  passwordManagedBy: 'Admin' | 'Self' | null;
}

interface PortalActivityRecord {
  id: string;
  timestamp: string;
  userId: string;
  linkedProfileId: string;
  actorName: string;
  actorRole: string;
  email: string;
  phone: string;
  action: string;
  entity: string;
  details: string;
}

interface VisitorEntryRecord {
  id: string;
  visitedAt: string;
  entryType: 'Auto Visit' | 'Manual Entry';
  visitorLabel: string;
  contact: string;
  device: string;
  browser: string;
  language: string;
  timezone: string;
  landingPage: string;
  referrer: string;
  screenSize: string;
  ipMasked: string;
  notes: string;
}

interface VisitorStatsRecord {
  totalVisits: number;
  todayDate: string;
  todayVisits: number;
  uniqueVisitorHashes: string[];
  visitorLogs: VisitorEntryRecord[];
}

interface PersistedAuthStore {
  runtimeSecret: string;
  claimedAdmin: ClaimedAdminRecord | null;
  userAccounts: UserAccountRecord[];
  portalActivities: PortalActivityRecord[];
  visitorStats: VisitorStatsRecord;
}

const DEFAULT_ROSTER: UserAccountRecord[] = [
  {
    id: 'usr-tch-tariqul',
    role: 'teacher',
    linkedProfileId: 'tch-tariqul',
    name: 'Ustadh Tariqul Islam',
    email: 'tariqul@saqafaacademy.com',
    phone: '+880 1711-000101',
    normalizedPhone: '8801711000101',
    salt: null,
    hashHex: null,
    approvalStatus: 'Pending',
    approvedAt: null,
    approvedBy: null,
    status: 'Active',
    createdAt: '2026-10-01',
    lastLoginAt: null,
    loginCount: 0,
    passwordUpdatedAt: null,
    passwordManagedBy: null,
  },
  {
    id: 'usr-tch-hasan',
    role: 'teacher',
    linkedProfileId: 'tch-hasan',
    name: 'Ustadh Hasan Al-Azhari',
    email: 'hasan@saqafaacademy.com',
    phone: '+880 1711-000102',
    normalizedPhone: '8801711000102',
    salt: null,
    hashHex: null,
    approvalStatus: 'Pending',
    approvedAt: null,
    approvedBy: null,
    status: 'Active',
    createdAt: '2026-10-01',
    lastLoginAt: null,
    loginCount: 0,
    passwordUpdatedAt: null,
    passwordManagedBy: null,
  },
  {
    id: 'usr-tch-abdullah',
    role: 'teacher',
    linkedProfileId: 'tch-abdullah',
    name: 'Ustadh Abdullah Al-Mahmud',
    email: 'abdullah@saqafaacademy.com',
    phone: '+966 50 100 0103',
    normalizedPhone: '966501000103',
    salt: null,
    hashHex: null,
    approvalStatus: 'Pending',
    approvedAt: null,
    approvedBy: null,
    status: 'Active',
    createdAt: '2026-10-01',
    lastLoginAt: null,
    loginCount: 0,
    passwordUpdatedAt: null,
    passwordManagedBy: null,
  },
  {
    id: 'usr-prt-rahman',
    role: 'parent',
    linkedProfileId: 'prt-rahman',
    name: 'Dr. Mahmudur Rahman',
    email: 'mahmudur.rahman@example.com',
    phone: '+1 (416) 555-0192',
    normalizedPhone: '14165550192',
    salt: null,
    hashHex: null,
    approvalStatus: 'Pending',
    approvedAt: null,
    approvedBy: null,
    status: 'Active',
    createdAt: '2026-10-02',
    lastLoginAt: null,
    loginCount: 0,
    passwordUpdatedAt: null,
    passwordManagedBy: null,
  },
  {
    id: 'usr-std-farhan',
    role: 'student',
    linkedProfileId: 'std-farhan',
    name: 'Farhan Hossain',
    email: 'farhan.hossain@example.com',
    phone: '+44 7700 900123',
    normalizedPhone: '447700900123',
    salt: null,
    hashHex: null,
    approvalStatus: 'Pending',
    approvedAt: null,
    approvedBy: null,
    status: 'Active',
    createdAt: '2026-10-18',
    lastLoginAt: null,
    loginCount: 0,
    passwordUpdatedAt: null,
    passwordManagedBy: null,
  },
  {
    id: 'usr-std-sara',
    role: 'student',
    linkedProfileId: 'std-sara',
    name: 'Sara Rahman',
    email: 'sara.rahman@example.com',
    phone: '+1 (416) 555-0194',
    normalizedPhone: '14165550194',
    salt: null,
    hashHex: null,
    approvalStatus: 'Pending',
    approvedAt: null,
    approvedBy: null,
    status: 'Active',
    createdAt: '2026-10-02',
    lastLoginAt: null,
    loginCount: 0,
    passwordUpdatedAt: null,
    passwordManagedBy: null,
  },
  {
    id: 'usr-std-ayaan',
    role: 'student',
    linkedProfileId: 'std-ayaan',
    name: 'Ayaan Rahman',
    email: 'ayaan.rahman@example.com',
    phone: '+1 (416) 555-0195',
    normalizedPhone: '14165550195',
    salt: null,
    hashHex: null,
    approvalStatus: 'Pending',
    approvedAt: null,
    approvedBy: null,
    status: 'Active',
    createdAt: '2026-10-02',
    lastLoginAt: null,
    loginCount: 0,
    passwordUpdatedAt: null,
    passwordManagedBy: null,
  },
];

const loadAuthStore = (): PersistedAuthStore => {
  try {
    if (fs.existsSync(AUTH_STORE_FILE)) {
      const raw = fs.readFileSync(AUTH_STORE_FILE, 'utf8');
      const parsed = JSON.parse(raw) as Partial<PersistedAuthStore>;
      return {
        runtimeSecret:
          typeof parsed.runtimeSecret === 'string' && parsed.runtimeSecret.length >= 32
            ? parsed.runtimeSecret
            : crypto.randomBytes(32).toString('hex'),
        claimedAdmin: parsed.claimedAdmin || null,
        userAccounts: Array.isArray(parsed.userAccounts)
          ? parsed.userAccounts.map((u) => ({
              ...u,
              approvalStatus: u.approvalStatus || (u.hashHex ? 'Approved' : 'Pending'),
              approvedAt: u.approvedAt ?? null,
              approvedBy: u.approvedBy ?? null,
            }))
          : [...DEFAULT_ROSTER],
        portalActivities: Array.isArray(parsed.portalActivities) ? parsed.portalActivities : [],
        visitorStats:
          parsed.visitorStats && typeof parsed.visitorStats.totalVisits === 'number'
            ? {
                totalVisits: parsed.visitorStats.totalVisits,
                todayDate:
                  typeof parsed.visitorStats.todayDate === 'string'
                    ? parsed.visitorStats.todayDate
                    : new Date().toISOString().slice(0, 10),
                todayVisits: typeof parsed.visitorStats.todayVisits === 'number' ? parsed.visitorStats.todayVisits : 0,
                uniqueVisitorHashes: Array.isArray(parsed.visitorStats.uniqueVisitorHashes)
                  ? parsed.visitorStats.uniqueVisitorHashes
                  : [],
                visitorLogs: Array.isArray(parsed.visitorStats.visitorLogs)
                  ? parsed.visitorStats.visitorLogs
                  : [],
              }
            : {
                totalVisits: 0,
                todayDate: new Date().toISOString().slice(0, 10),
                todayVisits: 0,
                uniqueVisitorHashes: [],
                visitorLogs: [],
              },
      };
    }
  } catch (err) {
    console.warn('Initializing fresh academy auth store:', err);
  }
  return {
    runtimeSecret: crypto.randomBytes(32).toString('hex'),
    claimedAdmin: null,
    userAccounts: [...DEFAULT_ROSTER],
    portalActivities: [],
    visitorStats: {
      totalVisits: 0,
      todayDate: new Date().toISOString().slice(0, 10),
      todayVisits: 0,
      uniqueVisitorHashes: [],
      visitorLogs: [],
    },
  };
};

const authStore: PersistedAuthStore = loadAuthStore();

const saveAuthStore = () => {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
    }
    fs.writeFileSync(AUTH_STORE_FILE, JSON.stringify(authStore, null, 2), { encoding: 'utf8', mode: 0o600 });
  } catch (err) {
    console.error('Failed to persist academy auth store:', err);
  }
};

// Persist initial runtime secret on boot if store file didn't exist yet
if (!fs.existsSync(AUTH_STORE_FILE)) {
  saveAuthStore();
}

const SESSION_SECRET =
  process.env.SESSION_SECRET && process.env.SESSION_SECRET.trim().length >= 16
    ? process.env.SESSION_SECRET.trim()
    : authStore.runtimeSecret;

const revokedTokenIds = new Set<string>();

interface RateLimitBucket {
  count: number;
  resetAt: number;
}
const loginAttemptsByIp = new Map<string, RateLimitBucket>();

const normalizePhoneDigits = (raw: string): string => raw.replace(/\D/g, '');

const phonesMatch = (storedDigits: string, inputDigits: string): boolean => {
  if (!storedDigits || !inputDigits || inputDigits.length < 7) return false;
  if (storedDigits === inputDigits) return true;
  const tailStored = storedDigits.slice(-10);
  const tailInput = inputDigits.slice(-10);
  return tailStored.length >= 9 && tailStored === tailInput;
};

const appendPortalActivity = (entry: Omit<PortalActivityRecord, 'id' | 'timestamp'>) => {
  authStore.portalActivities.unshift({
    id: `pact-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
    ...entry,
  });
  if (authStore.portalActivities.length > 300) {
    authStore.portalActivities.length = 300;
  }
  saveAuthStore();
};

const getClientIp = (req: Request): string => {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.trim()) {
    return fwd.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
};

const checkRateLimit = (ip: string): { allowed: boolean; retryAfterSec: number } => {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const maxAttempts = 25;
  const existing = loginAttemptsByIp.get(ip);

  if (!existing || existing.resetAt <= now) {
    loginAttemptsByIp.set(ip, { count: 1, resetAt: now + windowMs });
    return { allowed: true, retryAfterSec: 0 };
  }

  if (existing.count >= maxAttempts) {
    return { allowed: false, retryAfterSec: Math.ceil((existing.resetAt - now) / 1000) };
  }

  existing.count += 1;
  return { allowed: true, retryAfterSec: 0 };
};

const clearRateLimit = (ip: string) => {
  loginAttemptsByIp.delete(ip);
};

const getConfiguredPasscode = (): string | null => {
  const raw = process.env.ADMIN_PASSCODE;
  return raw && raw.trim().length > 0 ? raw.trim() : null;
};

const getEffectiveAdminEmail = (): string => {
  const envEmail = process.env.ADMIN_EMAIL?.trim();
  if (envEmail) return envEmail.toLowerCase();
  if (authStore.claimedAdmin) return authStore.claimedAdmin.email.toLowerCase();
  return DEFAULT_ADMIN_EMAIL;
};

const isValidEmail = (value: unknown): value is string => {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed) && trimmed.length <= 200;
};

const isPortalRole = (value: unknown): value is PortalRole =>
  value === 'teacher' || value === 'student' || value === 'parent';

const constantTimeStringEqual = (a: string, b: string): boolean => {
  const digestA = crypto.createHash('sha256').update(a, 'utf8').digest();
  const digestB = crypto.createHash('sha256').update(b, 'utf8').digest();
  return crypto.timingSafeEqual(digestA, digestB);
};

const hashPasswordScrypt = (password: string, saltHex: string): string =>
  crypto.scryptSync(password, saltHex, 64).toString('hex');

const signAdminToken = (email: string): string => {
  const payload: AdminSessionPayload = {
    sub: email.toLowerCase(),
    role: 'admin',
    jti: crypto.randomUUID(),
    exp: Date.now() + 12 * 60 * 60 * 1000,
  };
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
};

const verifyAdminToken = (token: string | undefined): AdminSessionPayload | null => {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  if (!body || !sig) return null;

  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  if (!constantTimeStringEqual(sig, expectedSig)) return null;

  try {
    const parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as AdminSessionPayload;
    if (!parsed || parsed.role !== 'admin' || typeof parsed.sub !== 'string' || typeof parsed.jti !== 'string') {
      return null;
    }
    if (typeof parsed.exp !== 'number' || parsed.exp <= Date.now()) {
      return null;
    }
    if (revokedTokenIds.has(parsed.jti)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
};

const signPortalToken = (account: UserAccountRecord): string => {
  const payload: PortalSessionPayload = {
    uid: account.id,
    role: account.role,
    linkedProfileId: account.linkedProfileId,
    name: account.name,
    email: account.email,
    phone: account.phone,
    jti: crypto.randomUUID(),
    exp: Date.now() + 12 * 60 * 60 * 1000,
  };
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
};

const verifyPortalToken = (token: string | undefined): PortalSessionPayload | null => {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  if (!body || !sig) return null;

  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  if (!constantTimeStringEqual(sig, expectedSig)) return null;

  try {
    const parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as PortalSessionPayload;
    if (!parsed || !isPortalRole(parsed.role) || typeof parsed.uid !== 'string' || typeof parsed.jti !== 'string') {
      return null;
    }
    if (typeof parsed.exp !== 'number' || parsed.exp <= Date.now()) {
      return null;
    }
    if (revokedTokenIds.has(parsed.jti)) {
      return null;
    }
    const account = authStore.userAccounts.find((u) => u.id === parsed.uid);
    if (!account || account.status !== 'Active' || account.approvalStatus !== 'Approved') {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
};

const extractBearerToken = (req: Request): string | undefined => {
  const auth = req.headers.authorization;
  if (!auth || typeof auth !== 'string') return undefined;
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : undefined;
};

const requireAdminAuth = (req: Request, res: Response, next: NextFunction) => {
  const payload = verifyAdminToken(extractBearerToken(req));
  if (!payload) {
    res.status(401).json({ error: 'Unauthorized: valid admin session required.' });
    return;
  }
  res.locals.adminSession = payload;
  next();
};

const requirePortalAuth = (req: Request, res: Response, next: NextFunction) => {
  const payload = verifyPortalToken(extractBearerToken(req));
  if (!payload) {
    res.status(401).json({ error: 'Unauthorized: valid approved user session required.' });
    return;
  }
  res.locals.portalSession = payload;
  next();
};

const toPublicUserDto = (account: UserAccountRecord) => ({
  id: account.id,
  role: account.role,
  linkedProfileId: account.linkedProfileId,
  name: account.name,
  email: account.email,
  phone: account.phone,
  hasPassword: Boolean(account.hashHex && account.salt),
  passwordManagedBy: account.passwordManagedBy,
  passwordUpdatedAt: account.passwordUpdatedAt,
  approvalStatus: account.approvalStatus,
  approvedAt: account.approvedAt,
  approvedBy: account.approvedBy,
  status: account.status,
  createdAt: account.createdAt,
  lastLoginAt: account.lastLoginAt,
  loginCount: account.loginCount,
});

const findAccountByIdentifier = (role: PortalRole, identifier: string): UserAccountRecord | undefined => {
  const trimmed = identifier.trim();
  if (isValidEmail(trimmed)) {
    const emailLower = trimmed.toLowerCase();
    return authStore.userAccounts.find((u) => u.role === role && u.email.toLowerCase() === emailLower);
  }
  if (role === 'teacher') {
    return undefined;
  }
  const digits = normalizePhoneDigits(trimmed);
  if (digits.length < 7) return undefined;
  return authStore.userAccounts.find((u) => u.role === role && phonesMatch(u.normalizedPhone, digits));
};

async function startServer() {
  const app = express();
  app.set('trust proxy', true);
  app.use(express.json({ limit: '64kb' }));

  const maskIpForLog = (ip: string): string => {
    if (!ip || ip === 'unknown') return 'Unknown';
    if (ip.includes('.')) {
      const parts = ip.split('.');
      if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.*`;
    }
    if (ip.includes(':')) {
      const parts = ip.split(':').filter(Boolean);
      return parts.length >= 2 ? `${parts[0]}:${parts[1]}::*` : ip;
    }
    return ip;
  };

  const parseUserAgentSummary = (ua: string): { device: string; browser: string } => {
    const lower = ua.toLowerCase();
    const device = /mobile|android|iphone|ipad|ipod/.test(lower)
      ? /ipad|tablet/.test(lower)
        ? 'Tablet'
        : 'Mobile'
      : 'Desktop';
    let browser = 'Browser';
    if (lower.includes('edg/')) browser = 'Edge';
    else if (lower.includes('chrome/') && !lower.includes('edg/')) browser = 'Chrome';
    else if (lower.includes('firefox/')) browser = 'Firefox';
    else if (lower.includes('safari/') && !lower.includes('chrome/')) browser = 'Safari';
    return { device, browser };
  };

  const getVisitorStatsDto = () => {
    const today = new Date().toISOString().slice(0, 10);
    if (authStore.visitorStats.todayDate !== today) {
      authStore.visitorStats.todayDate = today;
      authStore.visitorStats.todayVisits = 0;
      saveAuthStore();
    }
    return {
      totalVisits: authStore.visitorStats.totalVisits,
      todayVisits: authStore.visitorStats.todayVisits,
      uniqueVisitors: authStore.visitorStats.uniqueVisitorHashes.length,
      logs: authStore.visitorStats.visitorLogs,
    };
  };

  // ==========================================
  // VISITOR ANALYTICS & ENTRY ROUTES (LOGS ARE SUPER ADMIN ONLY)
  // ==========================================
  app.get('/api/visitors/summary', (_req: Request, res: Response) => {
    const today = new Date().toISOString().slice(0, 10);
    if (authStore.visitorStats.todayDate !== today) {
      authStore.visitorStats.todayDate = today;
      authStore.visitorStats.todayVisits = 0;
      saveAuthStore();
    }
    res.json({
      totalVisits: authStore.visitorStats.totalVisits,
      todayVisits: authStore.visitorStats.todayVisits,
    });
  });

  app.get('/api/visitors', requireAdminAuth, (_req: Request, res: Response) => {
    res.json(getVisitorStatsDto());
  });

  app.post('/api/visitors/hit', (req: Request, res: Response) => {
    const today = new Date().toISOString().slice(0, 10);
    if (authStore.visitorStats.todayDate !== today) {
      authStore.visitorStats.todayDate = today;
      authStore.visitorStats.todayVisits = 0;
    }

    authStore.visitorStats.totalVisits += 1;
    authStore.visitorStats.todayVisits += 1;

    const ip = getClientIp(req);
    const ua = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : 'unknown';
    const visitorHash = crypto.createHash('sha256').update(`${ip}|${ua}`).digest('hex').slice(0, 16);
    const isNewUnique = !authStore.visitorStats.uniqueVisitorHashes.includes(visitorHash);
    if (isNewUnique) {
      authStore.visitorStats.uniqueVisitorHashes.push(visitorHash);
      if (authStore.visitorStats.uniqueVisitorHashes.length > 10000) {
        authStore.visitorStats.uniqueVisitorHashes.shift();
      }
    }

    const body = (req.body || {}) as {
      language?: unknown;
      timezone?: unknown;
      landingPage?: unknown;
      referrer?: unknown;
      screenSize?: unknown;
    };
    const { device, browser } = parseUserAgentSummary(ua);
    const entry: VisitorEntryRecord = {
      id: `vis-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      visitedAt: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
      entryType: 'Auto Visit',
      visitorLabel: isNewUnique ? `New Visitor #${authStore.visitorStats.totalVisits}` : `Returning Visit #${authStore.visitorStats.totalVisits}`,
      contact: '',
      device,
      browser,
      language: typeof body.language === 'string' ? body.language.slice(0, 16) : 'bn',
      timezone: typeof body.timezone === 'string' ? body.timezone.slice(0, 64) : 'Unknown',
      landingPage: typeof body.landingPage === 'string' && body.landingPage.trim() ? body.landingPage.slice(0, 120) : '/',
      referrer: typeof body.referrer === 'string' && body.referrer.trim() ? body.referrer.slice(0, 140) : 'Direct',
      screenSize: typeof body.screenSize === 'string' ? body.screenSize.slice(0, 32) : '',
      ipMasked: maskIpForLog(ip),
      notes: '',
    };

    authStore.visitorStats.visitorLogs.unshift(entry);
    if (authStore.visitorStats.visitorLogs.length > 500) {
      authStore.visitorStats.visitorLogs.length = 500;
    }

    saveAuthStore();
    res.json({
      ok: true,
      totalVisits: authStore.visitorStats.totalVisits,
      todayVisits: authStore.visitorStats.todayVisits,
    });
  });

  app.post('/api/admin/visitors/manual', requireAdminAuth, (req: Request, res: Response) => {
    const adminSession = res.locals.adminSession as AdminSessionPayload;
    const { visitorLabel, contact, referrer, notes } = (req.body || {}) as {
      visitorLabel?: unknown;
      contact?: unknown;
      referrer?: unknown;
      notes?: unknown;
    };

    if (typeof visitorLabel !== 'string' || visitorLabel.trim().length < 2) {
      res.status(400).json({ error: 'Visitor name or label is required.' });
      return;
    }

    const entry: VisitorEntryRecord = {
      id: `vis-m-${Date.now()}-${Math.random().toString(36).slice(2, 5)}`,
      visitedAt: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
      entryType: 'Manual Entry',
      visitorLabel: visitorLabel.trim().slice(0, 100),
      contact: typeof contact === 'string' ? contact.trim().slice(0, 100) : '',
      device: 'Admin Desk',
      browser: 'Super Admin',
      language: 'bn',
      timezone: 'Asia/Dhaka',
      landingPage: 'Admin Entry',
      referrer: typeof referrer === 'string' && referrer.trim() ? referrer.trim().slice(0, 100) : 'Direct / Phone / WhatsApp',
      screenSize: '-',
      ipMasked: 'Verified by Admin',
      notes: typeof notes === 'string' ? notes.trim().slice(0, 300) : '',
    };

    authStore.visitorStats.visitorLogs.unshift(entry);
    if (authStore.visitorStats.visitorLogs.length > 500) {
      authStore.visitorStats.visitorLogs.length = 500;
    }
    saveAuthStore();

    appendPortalActivity({
      userId: 'admin',
      linkedProfileId: 'admin',
      actorName: `Super Admin (${adminSession.sub})`,
      actorRole: 'Admin',
      email: adminSession.sub,
      phone: '',
      action: 'ADMIN_RECORDED_VISITOR_ENTRY',
      entity: 'Visitor Data Ledger',
      details: `Added visitor data entry for ${entry.visitorLabel}${entry.contact ? ` (${entry.contact})` : ''}.`,
    });

    res.status(201).json({ entry, stats: getVisitorStatsDto() });
  });

  app.delete('/api/admin/visitors/:id', requireAdminAuth, (req: Request, res: Response) => {
    const idx = authStore.visitorStats.visitorLogs.findIndex((v) => v.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({ error: 'Visitor entry not found.' });
      return;
    }
    authStore.visitorStats.visitorLogs.splice(idx, 1);
    saveAuthStore();
    res.json(getVisitorStatsDto());
  });

  // ==========================================
  // SUPER ADMIN AUTH ROUTES
  // ==========================================
  app.get('/api/admin/auth/status', (req: Request, res: Response) => {
    const envPasscode = getConfiguredPasscode();
    const needsSetup = !envPasscode && authStore.claimedAdmin === null;
    const tokenPayload = verifyAdminToken(extractBearerToken(req));

    res.json({
      configured: !needsSetup,
      needsSetup,
      adminEmailHint: getEffectiveAdminEmail(),
      authenticated: Boolean(tokenPayload),
      adminEmail: tokenPayload ? tokenPayload.sub : null,
    });
  });

  app.post('/api/admin/auth/setup', (req: Request, res: Response) => {
    const envPasscode = getConfiguredPasscode();
    if (envPasscode || authStore.claimedAdmin !== null) {
      res.status(409).json({ error: 'Admin password is already configured on the server.' });
      return;
    }

    const { email, password } = (req.body || {}) as { email?: unknown; password?: unknown };
    if (!isValidEmail(email)) {
      res.status(400).json({ error: 'Please enter a valid academy email address.' });
      return;
    }
    if (typeof password !== 'string' || password.trim().length < 4 || password.length > 128) {
      res.status(400).json({ error: 'Password must be between 4 and 128 characters.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const expectedEmail = getEffectiveAdminEmail();
    if (process.env.ADMIN_EMAIL && normalizedEmail !== expectedEmail) {
      res.status(403).json({ error: 'Email does not match configured Academy Admin email.' });
      return;
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hashHex = hashPasswordScrypt(password.trim(), salt);
    authStore.claimedAdmin = {
      email: normalizedEmail,
      salt,
      hashHex,
      claimedAt: new Date().toISOString(),
    };
    saveAuthStore();

    appendPortalActivity({
      userId: 'admin',
      linkedProfileId: 'admin',
      actorName: 'Super Admin',
      actorRole: 'Admin',
      email: normalizedEmail,
      phone: '',
      action: 'ADMIN_INITIALIZED_ACCESS',
      entity: 'Super Admin Portal',
      details: 'Super Admin credential configured and signed in.',
    });

    const token = signAdminToken(normalizedEmail);
    res.status(201).json({
      token,
      adminEmail: normalizedEmail,
      role: 'admin',
    });
  });

  app.post('/api/admin/auth/login', (req: Request, res: Response) => {
    const ip = getClientIp(req);
    const rate = checkRateLimit(ip);
    if (!rate.allowed) {
      res.status(429).json({
        error: `Too many login attempts. Try again in ${rate.retryAfterSec} seconds.`,
      });
      return;
    }

    const envPasscode = getConfiguredPasscode();
    if (!envPasscode && !authStore.claimedAdmin) {
      res.status(409).json({ error: 'Admin access has not been configured yet. Set password first.' });
      return;
    }

    const { email, password } = (req.body || {}) as { email?: unknown; password?: unknown };
    if (!isValidEmail(email) || typeof password !== 'string' || !password.trim()) {
      res.status(400).json({ error: 'Valid email and password are required.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const expectedEmail = getEffectiveAdminEmail();
    if (!constantTimeStringEqual(normalizedEmail, expectedEmail)) {
      res.status(401).json({ error: 'Invalid academy email or password.' });
      return;
    }

    const submittedPassword = password.trim();
    let passwordMatched = false;

    if (envPasscode) {
      passwordMatched = constantTimeStringEqual(submittedPassword, envPasscode);
    } else if (authStore.claimedAdmin) {
      const candidateHex = hashPasswordScrypt(submittedPassword, authStore.claimedAdmin.salt);
      passwordMatched = constantTimeStringEqual(candidateHex, authStore.claimedAdmin.hashHex);
    }

    if (!passwordMatched) {
      res.status(401).json({ error: 'Invalid academy email or password.' });
      return;
    }

    clearRateLimit(ip);
    appendPortalActivity({
      userId: 'admin',
      linkedProfileId: 'admin',
      actorName: 'Super Admin',
      actorRole: 'Admin',
      email: normalizedEmail,
      phone: '',
      action: 'ADMIN_LOGIN',
      entity: 'Super Admin Portal',
      details: 'Authenticated into Super Admin dashboard.',
    });

    const token = signAdminToken(normalizedEmail);
    res.json({
      token,
      adminEmail: normalizedEmail,
      role: 'admin',
    });
  });

  app.post('/api/admin/auth/logout', (req: Request, res: Response) => {
    const payload = verifyAdminToken(extractBearerToken(req));
    if (payload) {
      revokedTokenIds.add(payload.jti);
    }
    res.json({ ok: true });
  });

  app.get('/api/admin/session', requireAdminAuth, (_req: Request, res: Response) => {
    const session = res.locals.adminSession as AdminSessionPayload;
    res.json({
      authenticated: true,
      role: session.role,
      adminEmail: session.sub,
      expiresAt: session.exp,
    });
  });

  // ==========================================
  // PORTAL USER ACCESS REQUEST & LOGIN ROUTES (TEACHER, STUDENT, PARENT)
  // ==========================================
  app.post('/api/portal/auth/request-access', (req: Request, res: Response) => {
    const ip = getClientIp(req);
    const rate = checkRateLimit(ip);
    if (!rate.allowed) {
      res.status(429).json({
        error: `Too many requests. Try again in ${rate.retryAfterSec} seconds.`,
      });
      return;
    }

    const { role, name, email, phone, password } = (req.body || {}) as {
      role?: unknown;
      name?: unknown;
      email?: unknown;
      phone?: unknown;
      password?: unknown;
    };

    if (!isPortalRole(role)) {
      res.status(400).json({ error: 'Please select Teacher, Student, or Parent.' });
      return;
    }
    if (typeof name !== 'string' || name.trim().length < 2) {
      res.status(400).json({ error: 'Full name is required (at least 2 characters).' });
      return;
    }
    if (typeof password !== 'string' || password.trim().length < 4 || password.length > 128) {
      res.status(400).json({ error: 'Password must be between 4 and 128 characters.' });
      return;
    }

    const cleanName = name.trim().slice(0, 100);
    const emailStr = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const phoneStr = typeof phone === 'string' ? phone.trim() : '';
    const phoneDigits = normalizePhoneDigits(phoneStr);

    if (role === 'teacher' && !isValidEmail(emailStr)) {
      res.status(400).json({ error: 'A valid email address is required for teacher access.' });
      return;
    }
    if (role !== 'teacher' && !emailStr && phoneDigits.length < 7) {
      res.status(400).json({ error: 'Provide either a valid email address or mobile number.' });
      return;
    }
    if (emailStr && !isValidEmail(emailStr)) {
      res.status(400).json({ error: 'Please enter a valid email address.' });
      return;
    }

    // Check if an APPROVED account already matches this email or phone
    const approvedExisting = authStore.userAccounts.find(
      (u) =>
        u.approvalStatus === 'Approved' &&
        u.hashHex &&
        ((emailStr && u.email.toLowerCase() === emailStr) ||
          (phoneDigits.length >= 7 && phonesMatch(u.normalizedPhone, phoneDigits)))
    );
    if (approvedExisting) {
      res.status(409).json({
        error: 'An approved account already exists with this email or mobile number. Please sign in directly.',
      });
      return;
    }

    // Check if there is an existing unactivated roster profile or pending/rejected request for this role & contact
    const matchingExisting = authStore.userAccounts.find((u) => {
      if (u.role !== role) return false;
      const emailMatch = Boolean(emailStr && u.email && u.email.toLowerCase() === emailStr);
      const phoneMatch = Boolean(phoneDigits.length >= 7 && phonesMatch(u.normalizedPhone, phoneDigits));
      return emailMatch || phoneMatch;
    });

    const nowStamp = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    const salt = crypto.randomBytes(16).toString('hex');
    const hashHex = hashPasswordScrypt(password.trim(), salt);

    if (matchingExisting) {
      matchingExisting.name = cleanName;
      if (emailStr) matchingExisting.email = emailStr;
      if (phoneStr) {
        matchingExisting.phone = phoneStr;
        matchingExisting.normalizedPhone = phoneDigits;
      }
      matchingExisting.salt = salt;
      matchingExisting.hashHex = hashHex;
      matchingExisting.approvalStatus = 'Pending';
      matchingExisting.approvedAt = null;
      matchingExisting.approvedBy = null;
      matchingExisting.passwordUpdatedAt = nowStamp;
      matchingExisting.passwordManagedBy = 'Self';
      saveAuthStore();

      appendPortalActivity({
        userId: matchingExisting.id,
        linkedProfileId: matchingExisting.linkedProfileId,
        actorName: matchingExisting.name,
        actorRole: matchingExisting.role,
        email: matchingExisting.email,
        phone: matchingExisting.phone,
        action: 'ACCESS_APPLICATION_SUBMITTED',
        entity: `${matchingExisting.role.toUpperCase()} #${matchingExisting.linkedProfileId}`,
        details: `Submitted password & access request awaiting Super Admin approval.`,
      });

      clearRateLimit(ip);
      res.status(201).json({
        ok: true,
        pendingApproval: true,
        application: toPublicUserDto(matchingExisting),
      });
      return;
    }

    // Ensure no cross-role pending collision
    const otherRoleCollision = authStore.userAccounts.find(
      (u) =>
        (emailStr && u.email.toLowerCase() === emailStr) ||
        (phoneDigits.length >= 7 && phonesMatch(u.normalizedPhone, phoneDigits))
    );
    if (otherRoleCollision) {
      res.status(409).json({
        error: 'This email or mobile number is already associated with another portal application.',
      });
      return;
    }

    const prefix = role === 'teacher' ? 'tch' : role === 'parent' ? 'prt' : 'std';
    const profileId = `${prefix}-${Date.now().toString().slice(-5)}`;

    const pendingRecord: UserAccountRecord = {
      id: `usr-${Date.now()}-${Math.random().toString(36).slice(2, 5)}`,
      role,
      linkedProfileId: profileId,
      name: cleanName,
      email: emailStr,
      phone: phoneStr,
      normalizedPhone: phoneDigits,
      salt,
      hashHex,
      approvalStatus: 'Pending',
      approvedAt: null,
      approvedBy: null,
      status: 'Active',
      createdAt: new Date().toISOString().slice(0, 10),
      lastLoginAt: null,
      loginCount: 0,
      passwordUpdatedAt: nowStamp,
      passwordManagedBy: 'Self',
    };

    authStore.userAccounts.unshift(pendingRecord);
    saveAuthStore();

    appendPortalActivity({
      userId: pendingRecord.id,
      linkedProfileId: pendingRecord.linkedProfileId,
      actorName: pendingRecord.name,
      actorRole: pendingRecord.role,
      email: pendingRecord.email,
      phone: pendingRecord.phone,
      action: 'ACCESS_APPLICATION_SUBMITTED',
      entity: `${pendingRecord.role.toUpperCase()} #${pendingRecord.linkedProfileId}`,
      details: `New ${pendingRecord.role} access request (${pendingRecord.email || pendingRecord.phone}) sent to Super Admin.`,
    });

    clearRateLimit(ip);
    res.status(201).json({
      ok: true,
      pendingApproval: true,
      application: toPublicUserDto(pendingRecord),
    });
  });

  app.post('/api/portal/auth/login', (req: Request, res: Response) => {
    const ip = getClientIp(req);
    const rate = checkRateLimit(ip);
    if (!rate.allowed) {
      res.status(429).json({
        error: `Too many login attempts. Try again in ${rate.retryAfterSec} seconds.`,
      });
      return;
    }

    const { role, identifier, password } = (req.body || {}) as {
      role?: unknown;
      identifier?: unknown;
      password?: unknown;
    };

    if (!isPortalRole(role)) {
      res.status(400).json({ error: 'Please select a valid portal role (teacher, student, or parent).' });
      return;
    }
    if (typeof identifier !== 'string' || !identifier.trim()) {
      res.status(400).json({
        error: role === 'teacher' ? 'Teacher email address is required.' : 'Email address or mobile number is required.',
      });
      return;
    }
    if (role === 'teacher' && !isValidEmail(identifier)) {
      res.status(400).json({ error: 'Teachers must sign in using their academy email address.' });
      return;
    }
    if (typeof password !== 'string' || !password.trim()) {
      res.status(400).json({ error: 'Password is required.' });
      return;
    }

    const cleanIdentifier = identifier.trim();
    const account = findAccountByIdentifier(role, cleanIdentifier);
    if (!account || !account.salt || !account.hashHex) {
      appendPortalActivity({
        userId: 'unregistered',
        linkedProfileId: 'none',
        actorName: cleanIdentifier,
        actorRole: role,
        email: cleanIdentifier.includes('@') ? cleanIdentifier : '',
        phone: !cleanIdentifier.includes('@') ? cleanIdentifier : '',
        action: 'PORTAL_LOGIN_ATTEMPT_NOT_FOUND',
        entity: `${role.toUpperCase()} Login`,
        details: `Login attempt for ${cleanIdentifier} (${role}) without an active configured account.`,
      });
      res.status(401).json({
        needsRequest: true,
        error: 'Account not found or password not configured yet. Please apply via Set Password & Apply first.',
      });
      return;
    }

    // Verify password first before revealing approval status
    const candidateHex = hashPasswordScrypt(password.trim(), account.salt);
    if (!constantTimeStringEqual(candidateHex, account.hashHex)) {
      appendPortalActivity({
        userId: account.id,
        linkedProfileId: account.linkedProfileId,
        actorName: account.name,
        actorRole: account.role,
        email: account.email,
        phone: account.phone,
        action: 'PORTAL_LOGIN_FAILED_PASSWORD',
        entity: `${account.role.toUpperCase()} Login`,
        details: `Incorrect password entered for ${account.name}.`,
      });
      res.status(401).json({ error: 'Invalid credentials or password.' });
      return;
    }

    if (account.approvalStatus === 'Pending') {
      appendPortalActivity({
        userId: account.id,
        linkedProfileId: account.linkedProfileId,
        actorName: account.name,
        actorRole: account.role,
        email: account.email,
        phone: account.phone,
        action: 'PORTAL_LOGIN_BLOCKED_PENDING',
        entity: `${account.role.toUpperCase()} #${account.linkedProfileId}`,
        details: `${account.name} attempted login while application is pending Super Admin approval.`,
      });
      res.status(403).json({
        approvalStatus: 'Pending',
        error: 'Your account is waiting for Super Admin approval. Once accepted, you can sign in with these credentials.',
      });
      return;
    }

    if (account.approvalStatus === 'Rejected') {
      appendPortalActivity({
        userId: account.id,
        linkedProfileId: account.linkedProfileId,
        actorName: account.name,
        actorRole: account.role,
        email: account.email,
        phone: account.phone,
        action: 'PORTAL_LOGIN_BLOCKED_REJECTED',
        entity: `${account.role.toUpperCase()} #${account.linkedProfileId}`,
        details: `${account.name} attempted login on a rejected application.`,
      });
      res.status(403).json({
        approvalStatus: 'Rejected',
        error: 'Your access application was not approved. Please contact Academy Administration.',
      });
      return;
    }

    if (account.status !== 'Active') {
      appendPortalActivity({
        userId: account.id,
        linkedProfileId: account.linkedProfileId,
        actorName: account.name,
        actorRole: account.role,
        email: account.email,
        phone: account.phone,
        action: 'PORTAL_LOGIN_BLOCKED_SUSPENDED',
        entity: `${account.role.toUpperCase()} #${account.linkedProfileId}`,
        details: `${account.name} attempted login on a suspended account.`,
      });
      res.status(403).json({ error: 'This account is suspended. Contact Saqafa Academy Administration.' });
      return;
    }

    clearRateLimit(ip);
    account.lastLoginAt = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    account.loginCount += 1;
    saveAuthStore();

    appendPortalActivity({
      userId: account.id,
      linkedProfileId: account.linkedProfileId,
      actorName: account.name,
      actorRole: account.role,
      email: account.email,
      phone: account.phone,
      action: 'PORTAL_LOGIN_SUCCESS',
      entity: `${account.role.toUpperCase()} Dashboard`,
      details: `${account.name} signed in (${account.email || account.phone}).`,
    });

    const token = signPortalToken(account);
    res.json({
      token,
      user: toPublicUserDto(account),
    });
  });

  app.get('/api/portal/session', requirePortalAuth, (_req: Request, res: Response) => {
    const session = res.locals.portalSession as PortalSessionPayload;
    const account = authStore.userAccounts.find((u) => u.id === session.uid);
    if (!account || account.approvalStatus !== 'Approved' || account.status !== 'Active') {
      res.status(401).json({ error: 'Account no longer active or approved.' });
      return;
    }
    res.json({
      authenticated: true,
      user: toPublicUserDto(account),
      expiresAt: session.exp,
    });
  });

  app.post('/api/portal/auth/logout', (req: Request, res: Response) => {
    const payload = verifyPortalToken(extractBearerToken(req));
    if (payload) {
      revokedTokenIds.add(payload.jti);
      appendPortalActivity({
        userId: payload.uid,
        linkedProfileId: payload.linkedProfileId,
        actorName: payload.name,
        actorRole: payload.role,
        email: payload.email,
        phone: payload.phone,
        action: 'PORTAL_LOGOUT',
        entity: `${payload.role.toUpperCase()} Dashboard`,
        details: `${payload.name} signed out.`,
      });
    }
    res.json({ ok: true });
  });

  app.post('/api/portal/activity', requirePortalAuth, (req: Request, res: Response) => {
    const session = res.locals.portalSession as PortalSessionPayload;
    const { action, entity, details } = (req.body || {}) as {
      action?: unknown;
      entity?: unknown;
      details?: unknown;
    };
    if (typeof action !== 'string' || !action.trim()) {
      res.status(400).json({ error: 'Action label is required.' });
      return;
    }
    appendPortalActivity({
      userId: session.uid,
      linkedProfileId: session.linkedProfileId,
      actorName: session.name,
      actorRole: session.role,
      email: session.email,
      phone: session.phone,
      action: action.trim().slice(0, 80),
      entity: typeof entity === 'string' ? entity.trim().slice(0, 120) : session.role,
      details: typeof details === 'string' ? details.trim().slice(0, 400) : '',
    });
    res.status(201).json({ ok: true });
  });

  // ==========================================
  // SUPER ADMIN USER GOVERNANCE, APPROVAL & ACTIVITY ENDPOINTS
  // ==========================================
  app.get('/api/admin/users', requireAdminAuth, (_req: Request, res: Response) => {
    res.json({
      users: authStore.userAccounts.map(toPublicUserDto),
      activities: authStore.portalActivities,
    });
  });

  app.post('/api/admin/users', requireAdminAuth, (req: Request, res: Response) => {
    const adminSession = res.locals.adminSession as AdminSessionPayload;
    const { role, name, email, phone, password, linkedProfileId } = (req.body || {}) as {
      role?: unknown;
      name?: unknown;
      email?: unknown;
      phone?: unknown;
      password?: unknown;
      linkedProfileId?: unknown;
    };

    if (!isPortalRole(role)) {
      res.status(400).json({ error: 'Role must be teacher, student, or parent.' });
      return;
    }
    if (typeof name !== 'string' || name.trim().length < 2) {
      res.status(400).json({ error: 'Full name is required.' });
      return;
    }
    const emailStr = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const phoneStr = typeof phone === 'string' ? phone.trim() : '';
    const phoneDigits = normalizePhoneDigits(phoneStr);

    if (role === 'teacher' && !isValidEmail(emailStr)) {
      res.status(400).json({ error: 'Valid email is required for teacher accounts.' });
      return;
    }
    if (!emailStr && phoneDigits.length < 7) {
      res.status(400).json({ error: 'Provide either an email address or a valid mobile number.' });
      return;
    }
    if (emailStr && !isValidEmail(emailStr)) {
      res.status(400).json({ error: 'Email format is invalid.' });
      return;
    }
    if (typeof password !== 'string' || password.trim().length < 4 || password.length > 128) {
      res.status(400).json({ error: 'Initial password must be between 4 and 128 characters.' });
      return;
    }

    const duplicate = authStore.userAccounts.find(
      (u) =>
        (emailStr && u.email.toLowerCase() === emailStr) ||
        (phoneDigits.length >= 7 && phonesMatch(u.normalizedPhone, phoneDigits))
    );
    if (duplicate) {
      res.status(409).json({ error: 'An account with this email or mobile number already exists.' });
      return;
    }

    const prefix = role === 'teacher' ? 'tch' : role === 'parent' ? 'prt' : 'std';
    const profileId =
      typeof linkedProfileId === 'string' && linkedProfileId.trim()
        ? linkedProfileId.trim()
        : `${prefix}-${Date.now().toString().slice(-5)}`;

    const salt = crypto.randomBytes(16).toString('hex');
    const nowStamp = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    const created: UserAccountRecord = {
      id: `usr-${Date.now()}-${Math.random().toString(36).slice(2, 5)}`,
      role,
      linkedProfileId: profileId,
      name: name.trim().slice(0, 100),
      email: emailStr,
      phone: phoneStr,
      normalizedPhone: phoneDigits,
      salt,
      hashHex: hashPasswordScrypt(password.trim(), salt),
      approvalStatus: 'Approved',
      approvedAt: nowStamp,
      approvedBy: adminSession.sub,
      status: 'Active',
      createdAt: new Date().toISOString().slice(0, 10),
      lastLoginAt: null,
      loginCount: 0,
      passwordUpdatedAt: nowStamp,
      passwordManagedBy: 'Admin',
    };

    authStore.userAccounts.unshift(created);
    saveAuthStore();

    appendPortalActivity({
      userId: 'admin',
      linkedProfileId: created.linkedProfileId,
      actorName: `Super Admin (${adminSession.sub})`,
      actorRole: 'Admin',
      email: created.email,
      phone: created.phone,
      action: 'ADMIN_CREATED_APPROVED_ACCOUNT',
      entity: `${created.role.toUpperCase()} #${created.linkedProfileId}`,
      details: `Created & approved login account for ${created.name} (${created.email || created.phone}).`,
    });

    res.status(201).json({ user: toPublicUserDto(created) });
  });

  app.post('/api/admin/users/:id/approve', requireAdminAuth, (req: Request, res: Response) => {
    const adminSession = res.locals.adminSession as AdminSessionPayload;
    const target = authStore.userAccounts.find((u) => u.id === req.params.id);
    if (!target) {
      res.status(404).json({ error: 'User application not found.' });
      return;
    }

    const { newPassword } = (req.body || {}) as { newPassword?: unknown };
    const nowStamp = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

    if (typeof newPassword === 'string' && newPassword.trim().length > 0) {
      if (newPassword.trim().length < 4 || newPassword.length > 128) {
        res.status(400).json({ error: 'Password must be between 4 and 128 characters.' });
        return;
      }
      const salt = crypto.randomBytes(16).toString('hex');
      target.salt = salt;
      target.hashHex = hashPasswordScrypt(newPassword.trim(), salt);
      target.passwordUpdatedAt = nowStamp;
      target.passwordManagedBy = 'Admin';
    }

    if (!target.salt || !target.hashHex) {
      res.status(400).json({ error: 'Set a password before approving this account.' });
      return;
    }

    target.approvalStatus = 'Approved';
    target.approvedAt = nowStamp;
    target.approvedBy = adminSession.sub;
    target.status = 'Active';
    saveAuthStore();

    appendPortalActivity({
      userId: 'admin',
      linkedProfileId: target.linkedProfileId,
      actorName: `Super Admin (${adminSession.sub})`,
      actorRole: 'Admin',
      email: target.email,
      phone: target.phone,
      action: 'ADMIN_APPROVED_USER_ACCESS',
      entity: `${target.role.toUpperCase()} #${target.linkedProfileId}`,
      details: `Approved portal access for ${target.name} (${target.email || target.phone}).`,
    });

    res.json({ user: toPublicUserDto(target) });
  });

  app.post('/api/admin/users/:id/reject', requireAdminAuth, (req: Request, res: Response) => {
    const adminSession = res.locals.adminSession as AdminSessionPayload;
    const target = authStore.userAccounts.find((u) => u.id === req.params.id);
    if (!target) {
      res.status(404).json({ error: 'User application not found.' });
      return;
    }

    target.approvalStatus = 'Rejected';
    target.approvedAt = null;
    target.approvedBy = adminSession.sub;
    saveAuthStore();

    appendPortalActivity({
      userId: 'admin',
      linkedProfileId: target.linkedProfileId,
      actorName: `Super Admin (${adminSession.sub})`,
      actorRole: 'Admin',
      email: target.email,
      phone: target.phone,
      action: 'ADMIN_REJECTED_USER_ACCESS',
      entity: `${target.role.toUpperCase()} #${target.linkedProfileId}`,
      details: `Rejected access application for ${target.name} (${target.email || target.phone}).`,
    });

    res.json({ user: toPublicUserDto(target) });
  });

  app.post('/api/admin/users/:id/reset-password', requireAdminAuth, (req: Request, res: Response) => {
    const adminSession = res.locals.adminSession as AdminSessionPayload;
    const target = authStore.userAccounts.find((u) => u.id === req.params.id);
    if (!target) {
      res.status(404).json({ error: 'User account not found.' });
      return;
    }
    const { newPassword } = (req.body || {}) as { newPassword?: unknown };
    if (typeof newPassword !== 'string' || newPassword.trim().length < 4 || newPassword.length > 128) {
      res.status(400).json({ error: 'New password must be between 4 and 128 characters.' });
      return;
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const nowStamp = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    target.salt = salt;
    target.hashHex = hashPasswordScrypt(newPassword.trim(), salt);
    target.passwordUpdatedAt = nowStamp;
    target.passwordManagedBy = 'Admin';
    target.approvalStatus = 'Approved';
    target.approvedAt = target.approvedAt || nowStamp;
    target.approvedBy = adminSession.sub;
    target.status = 'Active';
    saveAuthStore();

    appendPortalActivity({
      userId: 'admin',
      linkedProfileId: target.linkedProfileId,
      actorName: `Super Admin (${adminSession.sub})`,
      actorRole: 'Admin',
      email: target.email,
      phone: target.phone,
      action: 'ADMIN_SET_USER_PASSWORD',
      entity: `${target.role.toUpperCase()} #${target.linkedProfileId}`,
      details: `Super Admin updated password credential & ensured approved access for ${target.name}.`,
    });

    res.json({ user: toPublicUserDto(target) });
  });

  app.patch('/api/admin/users/:id/status', requireAdminAuth, (req: Request, res: Response) => {
    const adminSession = res.locals.adminSession as AdminSessionPayload;
    const target = authStore.userAccounts.find((u) => u.id === req.params.id);
    if (!target) {
      res.status(404).json({ error: 'User account not found.' });
      return;
    }
    const { status } = (req.body || {}) as { status?: unknown };
    if (status !== 'Active' && status !== 'Suspended') {
      res.status(400).json({ error: 'Status must be Active or Suspended.' });
      return;
    }

    target.status = status;
    saveAuthStore();

    appendPortalActivity({
      userId: 'admin',
      linkedProfileId: target.linkedProfileId,
      actorName: `Super Admin (${adminSession.sub})`,
      actorRole: 'Admin',
      email: target.email,
      phone: target.phone,
      action: 'ADMIN_CHANGED_USER_STATUS',
      entity: `${target.role.toUpperCase()} #${target.linkedProfileId}`,
      details: `Set account status of ${target.name} to ${status}.`,
    });

    res.json({ user: toPublicUserDto(target) });
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*all', (_req: Request, res: Response) => {
      const indexFile = path.join(distDir, 'index.html');
      if (fs.existsSync(indexFile)) {
        res.sendFile(indexFile);
      } else {
        res.status(404).send('Build not found. Run npm run build first.');
      }
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Saqafa Academy server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
