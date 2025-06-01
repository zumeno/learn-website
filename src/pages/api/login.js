export const prerender = false;
import { Pool } from 'pg';
import { generateSecretKeyHash, generateCode, decryptCode } from "../../lib/generateCodes.js";

const pool = new Pool({
  user: import.meta.env.DB_USER,
  host: 'localhost', 
  database: import.meta.env.DB_NAME,
  password: import.meta.env.DB_PASSWORD,
  port: 5432,
  max: 100, 
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

const email_secret = generateSecretKeyHash(import.meta.env.EMAIL_SECRET);
const password_secret = generateSecretKeyHash(import.meta.env.PASSWORD_SECRET);

export async function POST({ request }) {
  const origin = request.headers.get('origin');
  const requestUrl = new URL(request.url);

  const getRootDomain = (hostname) => {
    const parts = hostname.split('.');
    return parts.slice(-2).join('.'); 
  };

  const apiRootDomain = getRootDomain(requestUrl.hostname);
  const originRootDomain = origin ? getRootDomain(new URL(origin).hostname) : null;
    
  if (origin && originRootDomain !== apiRootDomain) {
    return new Response(JSON.stringify({ 
      error: 'forbidden',
      message: 'Access Denied'
    }), {
      status: 403,
      headers: { 
        'Content-Type': 'application/json',
        'Vary': 'Origin'
      }
    });
  }

  const contentType = request.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    return new Response(JSON.stringify({ 
      error: 'Invalid content type',
      message: 'Request must be JSON formatted'
    }), {
      status: 415,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    let requestBody;
    try {
      requestBody = await request.json();
    } catch (e) {
      return new Response(JSON.stringify({ 
        error: 'Invalid JSON',
        message: 'The request body contains malformed JSON'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const email = requestBody.email;
    const password = requestBody.password;

    if (!email || !password) {
      return new Response(JSON.stringify({ 
        error: 'Missing required fields',
        message: 'Both email and password are required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const client = await pool.connect();
    try {
      const profileQuery = 'SELECT email, encrypted_password FROM profiles WHERE email = $1';
      const profileResult = await client.query(profileQuery, [email]);

      if (profileResult.rows.length === 0) {
        return new Response(JSON.stringify({
          error: 'Authentication failed',
          message: 'No account found with this email address.'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      const profile = profileResult.rows[0];

      const correctPassword = decryptCode(profile.encrypted_password, password_secret);

      if (password != correctPassword) {
        return new Response(JSON.stringify({
          error: 'Authentication failed',
          message: 'Incorrect password. Please try again.'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }

    } finally {
      client.release();
    }

    return new Response(JSON.stringify({ 
      message: 'Login successful! Redirecting to dashboard...',
      emailCode: `${email}:${generateCode(email_secret, email)}`
    }), {
      status: 200,
      headers: { 
        'Content-Type': 'application/json',
        ...(origin && { 'Access-Control-Allow-Origin': origin }),
        'Vary': 'Origin'
      }
    });

  } catch (error) {
    console.error(error);
    
    return new Response(JSON.stringify({ 
      message: error.message,
    }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        ...(origin && { 'Access-Control-Allow-Origin': origin })
      }
    });
  }
}

export async function OPTIONS({ request }) {
  const origin = request.headers.get('origin');
  const requestUrl = new URL(request.url);

  const getRootDomain = (hostname) => {
    const parts = hostname.split('.');
    return parts.slice(-2).join('.'); 
  };

  const apiRootDomain = getRootDomain(requestUrl.hostname);
  const originRootDomain = origin ? getRootDomain(new URL(origin).hostname) : null;

  const isAllowedOrigin = originRootDomain === apiRootDomain;
  
  return new Response(null, {
    status: isAllowedOrigin ? 204 : 403,
    headers: {
      'Access-Control-Allow-Origin': isAllowedOrigin ? origin : '',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400', 
      'Access-Control-Allow-Credentials': 'true',
      'Vary': 'Origin, Access-Control-Request-Headers',
      ...(!isAllowedOrigin && {
        'Content-Type': 'text/plain',
        'Content-Length': '0'
      })
    }
  });
}
