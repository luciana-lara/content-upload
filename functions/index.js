const functions = require("firebase-functions");
const admin = require("firebase-admin");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { marked } = require("marked");
const express = require("express");

admin.initializeApp();

// Sandbox credentials (swap to production after app approval)
const CLIENT_KEY = 'sbawhogj1hyf04vlq1';
const CLIENT_SECRET = '84TCiZHcg7AzekWljCt7hrkpGSeyEIxh';
const REDIRECT_URI = 'https://media.thepom.app/auth/callback';
const MEDIA_BASE_URL = 'https://media.thepom.app';

// ─── Helpers ───

// Firebase Hosting only allows the "__session" cookie through its CDN.
// All other cookies are silently stripped. So we pack all token data into __session as JSON.

function getSession(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) cookies[k] = v.join('=');
  });
  try {
    return JSON.parse(decodeURIComponent(cookies.__session || ''));
  } catch {
    return {};
  }
}

function setSessionCookie(res, data) {
  const value = encodeURIComponent(JSON.stringify(data));
  res.set('Set-Cookie', `__session=${value}; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

function clearSessionCookie(res) {
  res.set('Set-Cookie', '__session=; Path=/; Max-Age=0');
}

function renderLegalPage(filename) {
  const filePath = path.join(__dirname, "content", filename);
  let md = fs.readFileSync(filePath, "utf-8");
  const today = new Date().toLocaleDateString("en-US", {
    year: "numeric", month: "long", day: "numeric",
  });
  md = md.replace(/\*\*Last Updated:.*?\*\*/g, `**Last Updated: ${today}**`);
  md = md.replace(/\*\*Effective Date:.*?\*\*/g, `**Effective Date: ${today}**`);
  const html = marked(md);
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${filename.replace(".md", "").replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px 20px 80px; line-height: 1.6; color: #333; }
  h1 { border-bottom: 2px solid #eee; padding-bottom: 10px; }
  h2 { margin-top: 2em; color: #222; }
  table { border-collapse: collapse; width: 100%; margin: 1em 0; }
  th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
  th { background: #f5f5f5; }
  a { color: #7C3AED; }
  hr { border: none; border-top: 1px solid #eee; margin: 2em 0; }
  code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
</style></head><body>${html}</body></html>`;
}

// ─── Legal pages ───

exports.privacyPolicy = functions.https.onRequest((req, res) => {
  res.set("Cache-Control", "public, max-age=3600");
  res.send(renderLegalPage("privacy-policy.md"));
});

exports.termsOfService = functions.https.onRequest((req, res) => {
  res.set("Cache-Control", "public, max-age=3600");
  res.send(renderLegalPage("terms-of-service.md"));
});

// ─── TikTok OAuth ───

exports.tiktokAuth = functions.https.onRequest((req, res) => {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  const scopes = 'user.info.basic,video.upload,video.publish';
  const csrfToken = crypto.randomBytes(16).toString('hex');
  const state = Buffer.from(JSON.stringify({ csrf: csrfToken, cv: codeVerifier })).toString('base64url');
  const params = new URLSearchParams({
    client_key: CLIENT_KEY, scope: scopes, response_type: 'code',
    redirect_uri: REDIRECT_URI, state, code_challenge: codeChallenge, code_challenge_method: 'S256'
  });
  const authUrl = `https://www.tiktok.com/v2/auth/authorize/?${params.toString()}`;
  res.set("Cache-Control", "private");
  res.redirect(authUrl);
});

exports.tiktokCallback = functions.https.onRequest(async (req, res) => {
  res.set("Cache-Control", "private");
  const { code, state, error, error_description } = req.query;
  if (error) return res.redirect(`/?error=${encodeURIComponent(error_description || error)}`);
  if (!code) return res.redirect('/?error=No+authorization+code+received');

  let codeVerifier;
  try {
    const stateData = JSON.parse(Buffer.from(state, 'base64url').toString());
    codeVerifier = stateData.cv;
  } catch (e) {}
  if (!codeVerifier) return res.redirect('/?error=Invalid+session+state');

  try {
    const tokenResponse = await fetch('https://open.tiktokapis.com/v2/oauth/token/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_key: CLIENT_KEY, client_secret: CLIENT_SECRET, code,
        grant_type: 'authorization_code', redirect_uri: REDIRECT_URI, code_verifier: codeVerifier
      })
    });
    const tokenData = await tokenResponse.json();
    if (tokenData.error || !tokenData.access_token) {
      throw new Error(tokenData.error_description || tokenData.error || 'Failed to get token');
    }
    const { access_token, refresh_token, open_id } = tokenData;
    setSessionCookie(res, { access_token, refresh_token, open_id });
    res.redirect('/?connected=true');
  } catch (err) {
    res.redirect(`/?error=${encodeURIComponent(err.message)}`);
  }
});

// ─── API (Express) ───

const app = express();
app.use(express.json({ limit: '50mb' }));

// Check session status
app.get('/api/session', (req, res) => {
  res.set("Cache-Control", "private");
  const session = getSession(req);
  res.json({ tiktok: !!session.access_token });
});

// Get TikTok creator info (required by TikTok guidelines before showing post page)
app.get('/api/creator-info', async (req, res) => {
  const session = getSession(req);
  const accessToken = session.access_token;
  if (!accessToken) return res.status(401).json({ error: 'Not connected to TikTok.' });

  let creatorData = {}, userData = {};

  try {
    const creatorRes = await fetch('https://open.tiktokapis.com/v2/post/publish/creator_info/query/', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json; charset=UTF-8'
      }
    });
    creatorData = await creatorRes.json();
  } catch (err) {
    console.warn('Creator info fetch failed:', err.message);
  }

  try {
    const userRes = await fetch('https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name,avatar_url', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    userData = await userRes.json();
  } catch (err) {
    console.warn('User info fetch failed:', err.message);
  }

  res.json({
    creator: creatorData.data || {},
    user: userData.data?.user || {}
  });
});

// Refresh TikTok access token
app.post('/api/refresh-token', async (req, res) => {
  const session = getSession(req);
  const refreshToken = session.refresh_token;
  if (!refreshToken) return res.status(401).json({ error: 'No refresh token.' });

  try {
    const tokenRes = await fetch('https://open.tiktokapis.com/v2/oauth/token/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_key: CLIENT_KEY,
        client_secret: CLIENT_SECRET,
        grant_type: 'refresh_token',
        refresh_token: refreshToken
      })
    });
    const tokenData = await tokenRes.json();
    if (tokenData.error || !tokenData.access_token) {
      throw new Error(tokenData.error_description || 'Refresh failed');
    }
    setSessionCookie(res, {
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token || refreshToken,
      open_id: session.open_id
    });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Scrape a URL and return text content (no secrets involved — CORS bypass only)
app.post('/api/scrape', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'No URL provided.' });

  try {
    const pageResponse = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; PomBot/1.0)' }
    });
    if (!pageResponse.ok) throw new Error(`Failed to fetch ${url}: ${pageResponse.status}`);
    const html = await pageResponse.text();

    const textContent = html
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      .replace(/<style[\s\S]*?<\/style>/gi, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .substring(0, 8000);

    res.json({ text: textContent });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Upload files to Firebase Storage, return URLs
app.post('/api/upload', async (req, res) => {
  const { files } = req.body;
  if (!files || !files.length) return res.status(400).json({ error: 'No files provided' });

  try {
    const bucket = admin.storage().bucket();
    const timestamp = Date.now();
    const urls = [];

    for (let i = 0; i < files.length; i++) {
      const { name, data, type } = files[i];
      const ext = type.includes('video') ? 'mp4' : 'jpg';
      const filename = `upload_${timestamp}_${i}.${ext}`;
      const file = bucket.file(`tiktok/${filename}`);

      const buffer = Buffer.from(data, 'base64');
      await file.save(buffer, { metadata: { contentType: type } });

      urls.push(`${MEDIA_BASE_URL}/${filename}`);
    }

    res.json({ urls });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Post to TikTok (photos or video)
app.post('/api/post', async (req, res) => {
  const session = getSession(req);
  const accessToken = session.access_token;
  if (!accessToken) return res.status(401).json({ error: 'Not connected to TikTok. Please authorize first.' });

  const {
    mediaType, imageUrls, videoUrl,
    title, description, privacyLevel,
    disableComment, disableDuet, disableStitch,
    brandContentToggle, brandOrganic, brandedContent
  } = req.body;

  if (!privacyLevel) return res.status(400).json({ error: 'Privacy level is required.' });

  try {
    let endpoint, body;

    if (mediaType === 'PHOTO') {
      const postInfo = {
        privacy_level: privacyLevel,
        disable_comment: disableComment !== false,
        auto_add_music: true
      };
      if (title) postInfo.title = title.substring(0, 90);
      if (description) postInfo.description = description.substring(0, 4000);
      if (brandContentToggle) {
        if (brandOrganic) postInfo.brand_organic_toggle = true;
        if (brandedContent) postInfo.brand_content_toggle = true;
      }

      endpoint = 'https://open.tiktokapis.com/v2/post/publish/content/init/';
      body = {
        media_type: 'PHOTO',
        post_mode: 'DIRECT_POST',
        post_info: postInfo,
        source_info: {
          source: 'PULL_FROM_URL',
          photo_images: imageUrls,
          photo_cover_index: 0
        }
      };
    } else {
      const postInfo = {
        title: (description || '').substring(0, 2200),
        privacy_level: privacyLevel,
        disable_comment: disableComment !== false,
        disable_duet: disableDuet !== false,
        disable_stitch: disableStitch !== false
      };
      if (brandContentToggle) {
        if (brandOrganic) postInfo.brand_organic_toggle = true;
        if (brandedContent) postInfo.brand_content_toggle = true;
      }

      endpoint = 'https://open.tiktokapis.com/v2/post/publish/video/init/';
      body = {
        post_info: postInfo,
        source_info: {
          source: 'PULL_FROM_URL',
          video_url: videoUrl
        }
      };
    }

    const tiktokRes = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json; charset=UTF-8'
      },
      body: JSON.stringify(body)
    });

    const result = await tiktokRes.json();
    if (result.error && result.error.code !== 'ok') {
      throw new Error(`TikTok: ${result.error.code} - ${result.error.message}`);
    }

    res.json({ publishId: result.data?.publish_id, status: 'success' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Check post status
app.post('/api/post-status', async (req, res) => {
  const session = getSession(req);
  const accessToken = session.access_token;
  if (!accessToken) return res.status(401).json({ error: 'Not connected to TikTok.' });

  try {
    const tiktokRes = await fetch('https://open.tiktokapis.com/v2/post/publish/status/fetch/', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json; charset=UTF-8'
      },
      body: JSON.stringify({ publish_id: req.body.publishId })
    });
    const result = await tiktokRes.json();
    res.json(result.data || result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete uploaded files after TikTok has pulled them
app.post('/api/cleanup', async (req, res) => {
  const { urls } = req.body;
  if (!urls?.length) return res.json({ ok: true });
  try {
    const bucket = admin.storage().bucket();
    for (const url of urls) {
      const filename = url.split('/').pop();
      await bucket.file(`tiktok/${filename}`).delete().catch(() => {});
    }
    res.json({ ok: true, deleted: urls.length });
  } catch (err) {
    res.json({ ok: true });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

exports.api = functions.https.onRequest(app);

// ─── Serve Media ───

exports.serveMedia = functions.https.onRequest(async (req, res) => {
  const filePath = req.path.replace(/^\//, "");
  if (!filePath) { res.status(400).send("No file specified"); return; }
  try {
    const bucket = admin.storage().bucket();
    const file = bucket.file(`tiktok/${filePath}`);
    const [exists] = await file.exists();
    if (!exists) { res.status(404).send("Not found"); return; }
    const [metadata] = await file.getMetadata();
    res.set("Content-Type", metadata.contentType || "image/jpeg");
    res.set("Cache-Control", "public, max-age=3600");
    const stream = file.createReadStream();
    stream.pipe(res);
  } catch (err) {
    console.error("serveMedia error:", err);
    res.status(500).send("Error serving file");
  }
});

