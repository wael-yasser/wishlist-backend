/**
 * Wishlist App Proxy backend.
 *
 * This service is called by Shopify's App Proxy at:
 *   https://<your-store>.myshopify.com/apps/wishlist/*
 * which Shopify forwards to:
 *   https://<this-server>/wishlist/*
 * with a `signature` query param you MUST verify (done below), and, when the
 * shopper is logged in, a `logged_in_customer_id` query param.
 *
 * As of Shopify's 2026 Dev Dashboard app model, there is no static Admin API
 * token to copy from the UI. Instead, this server requests a short-lived
 * access token itself using the app's Client ID + Client Secret (the
 * "client credentials grant"), caches it, and refreshes it automatically
 * before it expires (tokens last 24 hours).
 *
 * Requires Node 18+ (uses global fetch).
 */
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');

const {
  SHOPIFY_API_SECRET, // used to verify App Proxy signatures
  SHOPIFY_CLIENT_ID, // from Dev Dashboard > your app > Settings
  SHOPIFY_CLIENT_SECRET, // from Dev Dashboard > your app > Settings
  SHOPIFY_STORE_DOMAIN, // e.g. your-store.myshopify.com
  ADMIN_API_VERSION = '2026-04',
  PORT = 3000,
} = process.env;

if (
  !SHOPIFY_API_SECRET ||
  !SHOPIFY_CLIENT_ID ||
  !SHOPIFY_CLIENT_SECRET ||
  !SHOPIFY_STORE_DOMAIN
) {
  console.error(
    'Missing required env vars. Set SHOPIFY_API_SECRET, SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_SECRET, SHOPIFY_STORE_DOMAIN.'
  );
  process.exit(1);
}

const app = express();
app.use(express.json());

/**
 * Verifies the request actually came from Shopify's App Proxy.
 */
function verifyProxySignature(req, res, next) {
  const { signature, ...rest } = req.query;
  if (!signature) return res.status(401).send('Missing signature');

  const message = Object.keys(rest)
    .sort()
    .map((key) => {
      const value = Array.isArray(rest[key]) ? rest[key].join(',') : rest[key];
      return `${key}=${value}`;
    })
    .join('');

  const digest = crypto
    .createHmac('sha256', SHOPIFY_API_SECRET)
    .update(message)
    .digest('hex');

  const a = Buffer.from(digest, 'utf8');
  const b = Buffer.from(String(signature), 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).send('Invalid signature');
  }
  next();
}

function getCustomerGid(req) {
  const id = req.query.logged_in_customer_id;
  return id ? `gid://shopify/Customer/${id}` : null;
}

// --- Client credentials token handling -------------------------------

let cachedToken = null;
let tokenExpiresAt = 0;

async function getAccessToken() {
  if (cachedToken && Date.now() < tokenExpiresAt - 60_000) {
    return cachedToken;
  }

  const response = await fetch(
    `https://${SHOPIFY_STORE_DOMAIN}/admin/oauth/access_token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
      }),
    }
  );

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Token request failed: ${response.status} ${text}`);
  }

  const { access_token, expires_in } = await response.json();
  cachedToken = access_token;
  tokenExpiresAt = Date.now() + expires_in * 1000;
  return cachedToken;
}

async function adminGraphQL(query, variables) {
  const token = await getAccessToken();
  const res = await fetch(
    `https://${SHOPIFY_STORE_DOMAIN}/admin/api/${ADMIN_API_VERSION}/graphql.json`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': token,
      },
      body: JSON.stringify({ query, variables }),
    }
  );
  const data = await res.json();
  if (data.errors) throw new Error(JSON.stringify(data.errors));
  return data.data;
}

async function getWishlist(customerGid) {
  const query = `
    query getWishlist($id: ID!) {
      customer(id: $id) {
        metafield(namespace: "wishlist", key: "products") {
          value
        }
      }
    }
  `;
  const data = await adminGraphQL(query, { id: customerGid });
  const raw = data.customer?.metafield?.value;
  return raw ? JSON.parse(raw) : [];
}

async function setWishlist(customerGid, handles) {
  const mutation = `
    mutation setWishlist($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields: $metafields) {
        userErrors { field message }
      }
    }
  `;
  const variables = {
    metafields: [
      {
        ownerId: customerGid,
        namespace: 'wishlist',
        key: 'products',
        type: 'json',
        value: JSON.stringify(handles),
      },
    ],
  };
  const data = await adminGraphQL(mutation, variables);
  if (data.metafieldsSet.userErrors.length) {
    throw new Error(JSON.stringify(data.metafieldsSet.userErrors));
  }
}

app.get('/wishlist/get', verifyProxySignature, async (req, res) => {
  const customerGid = getCustomerGid(req);
  if (!customerGid) return res.json({ products: [] });

  try {
    const products = await getWishlist(customerGid);
    res.json({ products });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load wishlist' });
  }
});

app.post('/wishlist/add', verifyProxySignature, async (req, res) => {
  const customerGid = getCustomerGid(req);
  if (!customerGid) return res.status(401).json({ error: 'Not logged in' });

  const { productHandle, productHandles } = req.body || {};
  const toAdd = productHandles || (productHandle ? [productHandle] : []);
  if (!toAdd.length) return res.status(400).json({ error: 'No product handle provided' });

  try {
    const current = await getWishlist(customerGid);
    const merged = Array.from(new Set([...current, ...toAdd]));
    await setWishlist(customerGid, merged);
    res.json({ products: merged });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update wishlist' });
  }
});

app.post('/wishlist/remove', verifyProxySignature, async (req, res) => {
  const customerGid = getCustomerGid(req);
  if (!customerGid) return res.status(401).json({ error: 'Not logged in' });

  const { productHandle } = req.body || {};
  if (!productHandle) return res.status(400).json({ error: 'No product handle provided' });

  try {
    const current = await getWishlist(customerGid);
    const updated = current.filter((h) => h !== productHandle);
    await setWishlist(customerGid, updated);
    res.json({ products: updated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update wishlist' });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Wishlist proxy server running on port ${PORT}`));
