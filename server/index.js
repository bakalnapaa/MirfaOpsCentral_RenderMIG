import dotenv from 'dotenv';
import express from 'express';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 3000);
const supabaseUrl = String(process.env.SUPABASE_URL || '').trim();
const serviceRoleKey = String(process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
const allowedOrigins = String(process.env.FRONTEND_ORIGINS || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const authEmailDomain = 'users.mirfaopscentral.com';
const weatherOrderColumns = ['created_at', 'logged_at', 'recorded_at', 'timestamp', 'time', 'date', 'id'];
const dubaiOffsetMinutes = 4 * 60;

if (!supabaseUrl || !serviceRoleKey) {
  throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required');
}

const sbAdmin = createClient(supabaseUrl, serviceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false }
});

function resolveAllowedOrigin(origin) {
  const cleanOrigin = String(origin || '').trim();
  if (!cleanOrigin) return allowedOrigins.length ? allowedOrigins[0] : '*';
  if (!allowedOrigins.length) return cleanOrigin;
  return allowedOrigins.includes(cleanOrigin) ? cleanOrigin : '';
}

app.disable('x-powered-by');
app.use((req, res, next) => {
  const allowedOrigin = resolveAllowedOrigin(req.headers.origin);
  if (allowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  if (req.headers.origin && !allowedOrigin) {
    jsonError(res, 403, 'Origin not allowed by CORS', req.headers.origin);
    return;
  }

  next();
});
app.use(express.json({ limit: '1mb' }));

function normalizeErrorText(value, fallback = 'unknown error') {
  if (typeof value === 'string') {
    const clean = value.trim();
    return clean || fallback;
  }
  if (value && typeof value === 'object') {
    if (typeof value.message === 'string' && value.message.trim()) return value.message.trim();
    if (typeof value.msg === 'string' && value.msg.trim()) return value.msg.trim();
    if (typeof value.error === 'string' && value.error.trim()) return value.error.trim();
    try {
      return JSON.stringify(value);
    } catch (_) {
      return fallback;
    }
  }
  return fallback;
}

function jsonError(res, status, error, details = '') {
  res.status(status).json({
    error: normalizeErrorText(error),
    ...(details ? { details: normalizeErrorText(details, '') } : {})
  });
}

async function requireUser(req, res, next) {
  const authHeader = String(req.headers.authorization || '');
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  const token = match?.[1]?.trim();
  if (!token) {
    jsonError(res, 401, 'Missing bearer token');
    return;
  }

  const { data, error } = await sbAdmin.auth.getUser(token);
  if (error || !data?.user) {
    jsonError(res, 401, 'Invalid or expired session');
    return;
  }

  req.authUser = data.user;
  next();
}

async function loadAppUser(req, res, next) {
  const { data, error } = await sbAdmin
    .from('users')
    .select('id,username,first_name,last_name,role,status,shift')
    .eq('id', req.authUser.id)
    .maybeSingle();

  if (error) {
    jsonError(res, 500, 'Could not load user profile', error.message || 'unknown error');
    return;
  }

  if (!data) {
    jsonError(res, 403, 'User profile not found');
    return;
  }

  req.appUser = data;
  next();
}

function requireApprovedAppUser(req, res, next) {
  const status = String(req.appUser?.status || '').trim().toLowerCase();
  const role = String(req.appUser?.role || '').trim().toLowerCase();
  if (status && status !== 'approved' && role !== 'admin') {
    jsonError(res, 403, 'User is not approved');
    return;
  }
  next();
}

function requireAdmin(req, res, next) {
  const role = String(req.appUser?.role || '').trim().toLowerCase();
  if (role !== 'admin') {
    jsonError(res, 403, 'Admin access required');
    return;
  }
  next();
}

function normalizeUsername(value) {
  return String(value || '').trim().toLowerCase().replace(/\s+/g, '');
}

function toLoginEmail(username) {
  const normalized = normalizeUsername(username);
  return normalized ? `${normalized}@${authEmailDomain}` : '';
}

function normalizePwResetState(state) {
  const clean = String(state || '').trim().toLowerCase();
  return clean && clean !== 'none' ? clean : null;
}

function currentTimestampIso() {
  return new Date().toISOString();
}

function appUserDisplayName(appUser) {
  return `${appUser?.first_name || ''} ${appUser?.last_name || ''}`.trim();
}

function shiftedDubaiDate(date = new Date()) {
  return new Date(date.getTime() + dubaiOffsetMinutes * 60000);
}

function getDubaiParts(date = new Date()) {
  const shifted = shiftedDubaiDate(date);
  return {
    year: shifted.getUTCFullYear(),
    month: shifted.getUTCMonth(),
    day: shifted.getUTCDate(),
    hour: shifted.getUTCHours(),
    minute: shifted.getUTCMinutes()
  };
}

function dubaiDateToUtc(year, month, day, hour, minute) {
  return new Date(Date.UTC(year, month, day, hour, minute) - dubaiOffsetMinutes * 60000);
}

function getShiftWindowFor(shiftName, referenceDate = new Date()) {
  const { year, month, day, hour, minute } = getDubaiParts(referenceDate);
  let start = null;
  let end = null;

  if (shiftName === 'Morning Shift') {
    start = dubaiDateToUtc(year, month, day, 5, 30);
    end = dubaiDateToUtc(year, month, day, 15, 0);
  } else if (shiftName === 'Afternoon Shift') {
    start = dubaiDateToUtc(year, month, day, 13, 0);
    end = dubaiDateToUtc(year, month, day, 22, 30);
  } else if (shiftName === 'Night Shift') {
    const beforeCutoff = hour < 6 || (hour === 6 && minute < 30);
    if (beforeCutoff) {
      start = dubaiDateToUtc(year, month, day - 1, 21, 0);
      end = dubaiDateToUtc(year, month, day, 6, 30);
    } else {
      start = dubaiDateToUtc(year, month, day, 21, 0);
      end = dubaiDateToUtc(year, month, day + 1, 6, 30);
    }
  }

  return { start, end };
}

function isShiftActiveNowFor(shiftName, referenceDate = new Date()) {
  if (!shiftName) return false;
  const { start, end } = getShiftWindowFor(shiftName, referenceDate);
  return !!(start && end && referenceDate >= start && referenceDate <= end);
}

function isSameDubaiDay(a, b) {
  const pa = getDubaiParts(a);
  const pb = getDubaiParts(b);
  return pa.year === pb.year && pa.month === pb.month && pa.day === pb.day;
}

function canOperatorEditActivityNow(appUser, recordShift, recordCreatedAt) {
  const userShift = String(appUser?.shift || '').trim();
  if (!userShift || String(recordShift || '').trim() !== userShift) return false;

  const nowTs = new Date();
  const { start, end } = getShiftWindowFor(userShift, nowTs);
  if (!start || !end || nowTs < start || nowTs > end) return false;

  const actTime = new Date(recordCreatedAt);
  if (Number.isNaN(actTime.getTime())) return false;

  return isSameDubaiDay(actTime, nowTs) && actTime >= start && actTime <= end;
}

async function fetchLatestShiftInfoRecord() {
  const { data, error } = await sbAdmin
    .from('shift_info')
    .select('shift, checked_in_by, created_at')
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) throw error;
  return data || null;
}

function buildActivityCreationLogRows(activities, changedBy, changedById) {
  return (activities || []).flatMap((act) => {
    const changedAt = act.created_at || currentTimestampIso();
    const fields = [
      { label: 'IP', value: act.ip || null },
      { label: 'Type', value: act.activity_type || null },
      { label: 'Diagnosis', value: act.diagnosis || null },
      { label: 'Remarks', value: act.remarks || null },
      { label: 'Tech', value: act.tech || null },
      { label: 'Status', value: act.status || null },
      { label: 'Shift', value: act.shift || null },
      { label: 'Logged By', value: act.logged_by || null }
    ];

    return fields
      .filter((field) => field.value !== null && field.value !== '')
      .map((field) => ({
        activity_id: Number(act.id),
        changed_by: changedBy,
        changed_by_id: changedById,
        field_name: field.label,
        old_value: null,
        new_value: field.value,
        changed_at: changedAt
      }));
  });
}

function buildActivityUpdateLogRows(id, before, nextValues, changedBy, changedById) {
  const fieldMap = {
    ip:            { label: 'IP',        old: before.ip,            nw: nextValues.ip },
    activity_type: { label: 'Type',      old: before.activity_type, nw: nextValues.activity_type },
    diagnosis:     { label: 'Diagnosis', old: before.diagnosis,     nw: nextValues.diagnosis },
    remarks:       { label: 'Remarks',   old: before.remarks,       nw: nextValues.remarks },
    tech:          { label: 'Tech',      old: before.tech,          nw: nextValues.tech },
    status:        { label: 'Status',    old: before.status,        nw: nextValues.status },
    shift:         { label: 'Shift',     old: before.shift,         nw: nextValues.shift }
  };

  return Object.values(fieldMap)
    .filter((field) => (field.old || '') !== (field.nw || ''))
    .map((field) => ({
      activity_id: Number(id),
      changed_by: changedBy,
      changed_by_id: changedById,
      field_name: field.label,
      old_value: field.old || null,
      new_value: field.nw || null,
      changed_at: currentTimestampIso()
    }));
}

function btNormalizeStatus(status) {
  return String(status || '').trim().toUpperCase();
}

function btStatusToken(status) {
  const normalized = btNormalizeStatus(status);
  return normalized ? `[STATUS:${normalized}]` : '';
}

function btExtractStatusFromRemarks(remarks) {
  const match = String(remarks || '').match(/^\s*\[STATUS:([^\]]+)\]\s*/i);
  return btNormalizeStatus(match?.[1] || '');
}

function btStripStatusToken(remarks) {
  return String(remarks || '').replace(/^\s*\[STATUS:[^\]]+\]\s*/i, '').trim();
}

function btBuildRemarksWithStatus(remarks, status) {
  const cleanRemarks = btStripStatusToken(remarks);
  const token = btStatusToken(status);
  return token ? `${token}${cleanRemarks ? ` ${cleanRemarks}` : ''}` : cleanRemarks;
}

function btRowStatus(row) {
  return btNormalizeStatus(row?.status || btExtractStatusFromRemarks(row?.remarks));
}

function btRowRemarks(row) {
  return btStripStatusToken(row?.remarks || '');
}

function btHasMissingStatusColError(error) {
  const msg = normalizeErrorText(error).toLowerCase();
  return msg.includes("could not find the 'status' column of 'bitmain_activities'")
    || msg.includes('column bitmain_activities.status does not exist')
    || msg.includes('column "status" of relation "bitmain_activities" does not exist')
    || (msg.includes('bitmain_activities') && msg.includes('status') && msg.includes('does not exist'));
}

async function bitmainActivitiesHasStatusColumn(force = false) {
  if (!force && bitmainActivitiesHasStatusColumn.cache !== undefined) return bitmainActivitiesHasStatusColumn.cache;
  const { error } = await sbAdmin.from('bitmain_activities').select('status').limit(1);
  bitmainActivitiesHasStatusColumn.cache = !error || !btHasMissingStatusColError(error);
  return bitmainActivitiesHasStatusColumn.cache;
}

function buildBitmainActivityCreationLogRows(activities, changedBy, changedById) {
  return (activities || []).flatMap((act) => {
    const changedAt = act.created_at || currentTimestampIso();
    const fields = [
      { label: 'IP', value: act.ip || null },
      { label: 'Issue', value: act.issue || null },
      { label: 'Action Taken', value: act.action_taken || null },
      { label: 'Remarks', value: btRowRemarks(act) || null },
      { label: 'Status', value: btRowStatus(act) || null },
      { label: 'Operator', value: act.operator || null },
      { label: 'Shift', value: act.shift || null }
    ];

    return fields
      .filter((field) => field.value !== null && field.value !== '')
      .map((field) => ({
        activity_id: Number(act.id),
        changed_by: changedBy,
        changed_by_id: changedById,
        field_name: field.label,
        old_value: null,
        new_value: field.value,
        changed_at: changedAt
      }));
  });
}

function buildBitmainActivityUpdateLogRows(id, before, nextValues, changedBy, changedById) {
  const beforeStatus = btRowStatus(before);
  const beforeRemarks = btRowRemarks(before);
  const fieldMap = {
    ip:           { label: 'IP',           old: before.ip,           nw: nextValues.ip },
    issue:        { label: 'Issue',        old: before.issue,        nw: nextValues.issue },
    action_taken: { label: 'Action Taken', old: before.action_taken, nw: nextValues.action_taken },
    status:       { label: 'Status',       old: beforeStatus,        nw: nextValues.status },
    remarks:      { label: 'Remarks',      old: beforeRemarks,       nw: nextValues.remarks }
  };

  return Object.values(fieldMap)
    .filter((field) => (field.old || '') !== (field.nw || ''))
    .map((field) => ({
      activity_id: Number(id),
      changed_by: changedBy,
      changed_by_id: changedById,
      field_name: field.label,
      old_value: field.old || null,
      new_value: field.nw || null,
      changed_at: currentTimestampIso()
    }));
}

async function findPublicUserById(userId) {
  const { data, error } = await sbAdmin
    .from('users')
    .select('id,username,email,first_name,last_name,role,status,shift,pw_reset,created_at')
    .eq('id', userId)
    .maybeSingle();
  if (error) throw error;
  return data || null;
}

async function findExistingRegistration(username, email) {
  const [usernameRes, emailRes] = await Promise.all([
    sbAdmin.from('users').select('id,username,email,status').ilike('username', username).limit(1),
    sbAdmin.from('users').select('id,username,email,status').eq('email', email).limit(1)
  ]);

  if (usernameRes.error) throw usernameRes.error;
  if (emailRes.error) throw emailRes.error;

  return usernameRes.data?.[0] || emailRes.data?.[0] || null;
}

async function findAuthUserByEmail(email) {
  const normalizedEmail = String(email || '').trim().toLowerCase();
  if (!normalizedEmail) return null;

  const perPage = 200;
  for (let page = 1; page <= 25; page += 1) {
    const { data, error } = await sbAdmin.auth.admin.listUsers({ page, perPage });
    if (error) throw error;

    const users = data?.users || [];
    const found = users.find((user) => String(user.email || '').trim().toLowerCase() === normalizedEmail) || null;
    if (found) return found;
    if (users.length < perPage) break;
  }

  return null;
}

async function ensureOperatorProfile({ userId, username, firstName, lastName, email }) {
  const payload = {
    id: userId,
    username,
    email,
    first_name: firstName,
    last_name: lastName,
    role: 'operator',
    status: 'pending',
    shift: null,
    pw_reset: normalizePwResetState('')
  };

  const { error } = await sbAdmin
    .from('users')
    .upsert(payload, { onConflict: 'id' });

  if (error) throw error;
  return findPublicUserById(userId);
}

async function fetchAdminQueue() {
  const [pendingRes, pwResetRes] = await Promise.all([
    sbAdmin.from('users')
      .select('id,first_name,last_name,username,created_at')
      .eq('status', 'pending')
      .neq('role', 'admin')
      .order('created_at', { ascending: false }),
    sbAdmin.from('users')
      .select('id,first_name,last_name,username,created_at')
      .eq('pw_reset', 'requested')
      .neq('role', 'admin')
      .order('created_at', { ascending: false })
  ]);

  if (pendingRes.error) throw pendingRes.error;
  if (pwResetRes.error) throw pwResetRes.error;

  return {
    pending: pendingRes.data || [],
    pwResets: pwResetRes.data || []
  };
}

async function fetchLatestWeatherLog() {
  const cols = 'temperature,humidity,dew_point,wet_bulb';

  for (const orderColumn of weatherOrderColumns) {
    try {
      const { data, error } = await sbAdmin
        .from('weather_logs')
        .select(cols)
        .order(orderColumn, { ascending: false })
        .limit(1);

      if (!error && data?.length) return data[0];
    } catch (_) {
      // Continue through likely timestamp columns for schema differences.
    }
  }

  const { data, error } = await sbAdmin
    .from('weather_logs')
    .select(cols)
    .limit(1);

  if (error) throw error;
  return data?.[0] || null;
}

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'mirfaopscentral-api',
    cors_mode: allowedOrigins.length ? 'restricted' : 'allow-all',
    allowed_origins: allowedOrigins
  });
});

app.post('/api/auth/register', async (req, res) => {
  const firstName = String(req.body?.firstName || '').trim();
  const lastName = String(req.body?.lastName || '').trim();
  const username = normalizeUsername(req.body?.username || '');
  const password = String(req.body?.password || '');

  if (!firstName || !lastName || !username || !password) {
    jsonError(res, 400, 'First name, last name, username, and password are required');
    return;
  }

  if (password.length < 8) {
    jsonError(res, 400, 'Password must be at least 8 characters');
    return;
  }

  const email = toLoginEmail(username);

  try {
    const existing = await findExistingRegistration(username, email);
    if (existing) {
      const status = String(existing.status || 'pending').trim().toLowerCase();
      if (status === 'approved') {
        jsonError(res, 409, 'This account already exists and is approved. Please sign in.');
        return;
      }
      if (status === 'suspended') {
        jsonError(res, 409, 'This account exists but is suspended. Contact admin.');
        return;
      }
      jsonError(res, 409, 'Registration already submitted and awaiting admin approval.');
      return;
    }

    const orphanedAuthUser = await findAuthUserByEmail(email);
    if (orphanedAuthUser?.id) {
      const recoveredProfile = await ensureOperatorProfile({
        userId: orphanedAuthUser.id,
        username,
        firstName,
        lastName,
        email
      });

      const recoveredStatus = String(recoveredProfile?.status || 'pending').trim().toLowerCase();
      if (recoveredStatus === 'approved') {
        jsonError(res, 409, 'This account already exists and is approved. Please sign in.');
        return;
      }
      if (recoveredStatus === 'suspended') {
        jsonError(res, 409, 'This account exists but is suspended. Contact admin.');
        return;
      }

      res.status(200).json({
        message: 'Registration recovered. The account is now pending admin approval.',
        user: recoveredProfile || {
          id: orphanedAuthUser.id,
          username,
          email,
          first_name: firstName,
          last_name: lastName,
          role: 'operator',
          status: 'pending',
          shift: '',
          pw_reset: normalizePwResetState('')
        }
      });
      return;
    }

    let authUser = null;
    const { data: created, error: createError } = await sbAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: {
        username,
        first_name: firstName,
        last_name: lastName
      }
    });

    if (createError) {
      const msg = normalizeErrorText(createError).toLowerCase();
      if (msg.includes('already registered') || msg.includes('already exists')) {
        authUser = await findAuthUserByEmail(email);
      } else {
        throw createError;
      }
    } else {
      authUser = created?.user || null;
    }

    if (!authUser?.id) {
      jsonError(res, 500, 'Could not create or recover the auth account');
      return;
    }

    const profile = await ensureOperatorProfile({
      userId: authUser.id,
      username,
      firstName,
      lastName,
      email
    });

    res.status(201).json({
      message: 'Account created. It is now pending admin approval.',
      user: profile || {
        id: authUser.id,
        username,
        email,
        first_name: firstName,
        last_name: lastName,
        role: 'operator',
        status: 'pending',
        shift: '',
        pw_reset: normalizePwResetState('')
      }
    });
  } catch (error) {
    jsonError(res, 500, 'Registration failed', normalizeErrorText(error));
  }
});

app.get('/api/auth/me', requireUser, loadAppUser, (req, res) => {
  res.json({
    user: {
      id: req.appUser.id,
      username: req.appUser.username,
      first_name: req.appUser.first_name,
      last_name: req.appUser.last_name,
      role: req.appUser.role,
      status: req.appUser.status,
      shift: req.appUser.shift
    }
  });
});

app.post('/api/activities/submer', requireUser, loadAppUser, requireApprovedAppUser, async (req, res) => {
  const rows = Array.isArray(req.body?.rows) ? req.body.rows : [];
  if (!rows.length) {
    jsonError(res, 400, 'No activities to save.');
    return;
  }

  const operatorName = appUserDisplayName(req.appUser);
  const operatorId = req.appUser.id || null;

  try {
    const latestShift = await fetchLatestShiftInfoRecord();
    const currentShift = latestShift?.shift || '';
    const inserts = rows.map((row) => ({
      ip: String(row?.ip || '').trim(),
      activity_type: String(row?.type || '').trim(),
      status: String(row?.status || '').trim().toUpperCase() || null,
      diagnosis: String(row?.diagnosis || '').trim(),
      remarks: String(row?.remarks || '').trim(),
      tech: String(row?.tech || '').trim(),
      shift: currentShift,
      logged_by: operatorName,
      logged_by_id: operatorId,
      created_at: currentTimestampIso()
    }));

    if (inserts.some((row) => !row.activity_type)) {
      jsonError(res, 400, 'Each activity requires a type.');
      return;
    }
    if (inserts.some((row) => !row.status)) {
      jsonError(res, 400, 'Each activity requires a status.');
      return;
    }

    const { data: createdActivities, error } = await sbAdmin
      .from('activities')
      .insert(inserts)
      .select('id,activity_type,ip,diagnosis,remarks,tech,status,shift,logged_by,logged_by_id,created_at');
    if (error) throw error;

    const createdLogRows = buildActivityCreationLogRows(createdActivities, operatorName, operatorId);
    if (createdLogRows.length) {
      const { error: logError } = await sbAdmin.from('activity_log').insert(createdLogRows);
      if (logError) throw logError;
    }

    res.status(201).json({ activities: createdActivities || [] });
  } catch (error) {
    jsonError(res, 500, 'Error saving activities', normalizeErrorText(error));
  }
});

app.patch('/api/activities/submer/:id', requireUser, loadAppUser, requireApprovedAppUser, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id <= 0) {
    jsonError(res, 400, 'Valid activity id is required.');
    return;
  }

  try {
    const { data: before, error: loadError } = await sbAdmin
      .from('activities')
      .select('*')
      .eq('id', id)
      .maybeSingle();
    if (loadError || !before) {
      jsonError(res, 404, 'Could not load activity.');
      return;
    }

    const isAdmin = String(req.appUser.role || '').trim().toLowerCase() === 'admin';
    if (!isAdmin && !canOperatorEditActivityNow(req.appUser, before.shift || '', before.created_at)) {
      jsonError(res, 403, 'You can only edit activities logged today within your active shift.');
      return;
    }

    const payload = {
      ip: String(req.body?.ip || '').trim(),
      activity_type: String(req.body?.type || '').trim(),
      diagnosis: String(req.body?.diagnosis || '').trim(),
      remarks: String(req.body?.remarks || '').trim(),
      tech: String(req.body?.tech || '').trim(),
      status: String(req.body?.status || '').trim().toUpperCase() || null,
      shift: String(req.body?.transferShift || before.shift || '').trim()
    };

    if (!payload.activity_type) {
      jsonError(res, 400, 'Please select a type.');
      return;
    }

    const { error } = await sbAdmin.from('activities').update(payload).eq('id', id);
    if (error) throw error;

    const logRows = buildActivityUpdateLogRows(id, before, payload, appUserDisplayName(req.appUser), req.appUser.id || null);
    if (logRows.length) {
      const { error: logError } = await sbAdmin.from('activity_log').insert(logRows);
      if (logError) throw logError;
    }

    const { data: updatedActivity, error: reloadError } = await sbAdmin
      .from('activities')
      .select('*')
      .eq('id', id)
      .maybeSingle();
    if (reloadError) throw reloadError;

    res.json({ activity: updatedActivity || { id, ...payload } });
  } catch (error) {
    jsonError(res, 500, 'Error saving activity', normalizeErrorText(error));
  }
});

app.post('/api/activities/bitmain', requireUser, loadAppUser, requireApprovedAppUser, async (req, res) => {
  const rows = Array.isArray(req.body?.rows) ? req.body.rows : [];
  if (!rows.length) {
    jsonError(res, 400, 'No activities to save.');
    return;
  }

  const operatorName = appUserDisplayName(req.appUser);
  const operatorId = req.appUser.id || null;
  const shift = String(req.body?.shift || req.appUser.shift || '').trim();

  try {
    const hasStatusColumn = await bitmainActivitiesHasStatusColumn();
    const buildInsertRows = (includeStatus) => rows.map((row) => {
      const status = btNormalizeStatus(row?.status || '');
      const remarks = String(row?.remarks || '').trim();
      return {
        ip: String(row?.ip || '').trim(),
        issue: String(row?.issue || '').trim(),
        action_taken: String(row?.action || '').trim(),
        remarks: includeStatus ? remarks : btBuildRemarksWithStatus(remarks, status),
        ...(includeStatus ? { status } : {}),
        operator: operatorName,
        operator_id: operatorId,
        shift,
        created_at: currentTimestampIso()
      };
    });

    if (rows.some((row) => !String(row?.status || '').trim())) {
      jsonError(res, 400, 'Each Bitmain activity requires a status.');
      return;
    }

    let inserts = buildInsertRows(hasStatusColumn);
    let { data: createdActivities, error } = await sbAdmin
      .from('bitmain_activities')
      .insert(inserts)
      .select('id,ip,issue,action_taken,remarks,status,operator,shift,created_at');
    if (error && hasStatusColumn && btHasMissingStatusColError(error)) {
      bitmainActivitiesHasStatusColumn.cache = false;
      inserts = buildInsertRows(false);
      ({ data: createdActivities, error } = await sbAdmin
        .from('bitmain_activities')
        .insert(inserts)
        .select('id,ip,issue,action_taken,remarks,status,operator,shift,created_at'));
    }
    if (error) throw error;

    const createdLogRows = buildBitmainActivityCreationLogRows(createdActivities, operatorName, operatorId);
    if (createdLogRows.length) {
      const { error: logError } = await sbAdmin.from('bitmain_activity_log').insert(createdLogRows);
      if (logError) throw logError;
    }

    res.status(201).json({ activities: createdActivities || [] });
  } catch (error) {
    jsonError(res, 500, 'Error saving Bitmain activities', normalizeErrorText(error));
  }
});

app.patch('/api/activities/bitmain/:id', requireUser, loadAppUser, requireApprovedAppUser, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id <= 0) {
    jsonError(res, 400, 'Valid activity id is required.');
    return;
  }

  try {
    const operatorName = appUserDisplayName(req.appUser);
    const operatorId = req.appUser.id || null;
    const { data: before, error: loadError } = await sbAdmin
      .from('bitmain_activities')
      .select('*')
      .eq('id', id)
      .maybeSingle();
    if (loadError || !before) {
      jsonError(res, 404, 'Could not load activity.');
      return;
    }

    const isAdmin = String(req.appUser.role || '').trim().toLowerCase() === 'admin';
    if (!isAdmin && !canOperatorEditActivityNow(req.appUser, before.shift || '', before.created_at)) {
      jsonError(res, 403, 'You can only edit activities from your active shift today.');
      return;
    }

    const status = btNormalizeStatus(req.body?.status || '');
    if (!status) {
      jsonError(res, 400, 'Please select a status.');
      return;
    }

    const basePayload = {
      ip: String(req.body?.ip || '').trim(),
      issue: String(req.body?.issue || '').trim(),
      action_taken: String(req.body?.action || '').trim()
    };
    const hasStatusColumn = await bitmainActivitiesHasStatusColumn();
    const payloadWithStatus = { ...basePayload, remarks: String(req.body?.remarks || '').trim(), status };
    const payloadFallback = { ...basePayload, remarks: btBuildRemarksWithStatus(String(req.body?.remarks || '').trim(), status) };
    let payload = hasStatusColumn ? payloadWithStatus : payloadFallback;
    let { error } = await sbAdmin.from('bitmain_activities').update(payload).eq('id', id);
    if (error && hasStatusColumn && btHasMissingStatusColError(error)) {
      bitmainActivitiesHasStatusColumn.cache = false;
      payload = payloadFallback;
      ({ error } = await sbAdmin.from('bitmain_activities').update(payload).eq('id', id));
    }
    if (error) throw error;

    const logRows = buildBitmainActivityUpdateLogRows(
      id,
      before,
      {
        ip: payload.ip,
        issue: payload.issue,
        action_taken: payload.action_taken,
        status,
        remarks: String(req.body?.remarks || '').trim()
      },
      operatorName,
      operatorId
    );
    if (logRows.length) {
      const { error: logError } = await sbAdmin.from('bitmain_activity_log').insert(logRows);
      if (logError) throw logError;
    }

    const { data: updatedActivity, error: reloadError } = await sbAdmin
      .from('bitmain_activities')
      .select('*')
      .eq('id', id)
      .maybeSingle();
    if (reloadError) throw reloadError;

    res.json({ activity: updatedActivity || { id, ...payload } });
  } catch (error) {
    jsonError(res, 500, 'Error saving Bitmain activity', normalizeErrorText(error));
  }
});

app.get('/api/admin/users/queue', requireUser, loadAppUser, requireAdmin, async (_req, res) => {
  try {
    const queue = await fetchAdminQueue();
    res.json(queue);
  } catch (error) {
    jsonError(res, 500, 'Could not load admin queue', error?.message || 'unknown error');
  }
});

app.post('/api/admin/users/:id/status', requireUser, loadAppUser, requireAdmin, async (req, res) => {
  const userId = String(req.params.id || '').trim();
  const status = String(req.body?.status || '').trim().toLowerCase();
  if (!userId) {
    jsonError(res, 400, 'User id is required');
    return;
  }
  if (!['pending', 'approved', 'suspended'].includes(status)) {
    jsonError(res, 400, 'Unsupported user status');
    return;
  }

  try {
    const { error } = await sbAdmin.from('users').update({ status }).eq('id', userId);
    if (error) throw error;
    const user = await findPublicUserById(userId);
    res.json({ user });
  } catch (error) {
    jsonError(res, 500, 'Could not update user status', error?.message || 'unknown error');
  }
});

app.post('/api/admin/users/:id/pw-reset-state', requireUser, loadAppUser, requireAdmin, async (req, res) => {
  const userId = String(req.params.id || '').trim();
  const state = String(req.body?.state || '').trim().toLowerCase();
  if (!userId) {
    jsonError(res, 400, 'User id is required');
    return;
  }
  if (!['none', 'requested', 'approved'].includes(state)) {
    jsonError(res, 400, 'Unsupported password reset state');
    return;
  }

  try {
    const { error } = await sbAdmin
      .from('users')
      .update({ pw_reset: normalizePwResetState(state) })
      .eq('id', userId);
    if (error) throw error;
    const user = await findPublicUserById(userId);
    res.json({ user });
  } catch (error) {
    jsonError(res, 500, 'Could not update password reset state', error?.message || 'unknown error');
  }
});

app.delete('/api/admin/users/:id', requireUser, loadAppUser, requireAdmin, async (req, res) => {
  const userId = String(req.params.id || '').trim();
  if (!userId) {
    jsonError(res, 400, 'User id is required');
    return;
  }

  try {
    const { error: authError } = await sbAdmin.auth.admin.deleteUser(userId);
    if (authError) {
      const msg = String(authError.message || '').toLowerCase();
      if (!msg.includes('not found')) throw authError;
    }

    const { error: profileError } = await sbAdmin.from('users').delete().eq('id', userId);
    if (profileError) throw profileError;

    res.status(204).send();
  } catch (error) {
    jsonError(res, 500, 'Could not delete user', error?.message || 'unknown error');
  }
});

app.get('/api/site-operations/weather/latest', requireUser, loadAppUser, requireApprovedAppUser, async (_req, res) => {
  try {
    const weather = await fetchLatestWeatherLog();
    res.json({ weather });
  } catch (error) {
    jsonError(res, 500, 'Could not load latest weather', error?.message || 'unknown error');
  }
});

app.listen(port, () => {
  console.log(`MirfaOpsCentral API listening on port ${port}`);
});
