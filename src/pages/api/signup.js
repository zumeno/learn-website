export const prerender = false;
import { Pool } from 'pg';
import { generateSecretKeyHash, generateCode, generateVerificationURL } from "../../lib/generateCodes.js";
import { sendVerificationEmail } from "../../lib/sendVerificationEmail.js";

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

const product_name = import.meta.env.PRODUCT_NAME;
const verification_secret = generateSecretKeyHash(import.meta.env.VERIFICATION_SECRET);
const email_secret = generateSecretKeyHash(import.meta.env.EMAIL_SECRET);
const password_secret = generateSecretKeyHash(import.meta.env.PASSWORD_SECRET);
const timestamp_secret = generateSecretKeyHash(import.meta.env.TIMESTAMP_SECRET);
const attempt_timestamp_secret = generateSecretKeyHash(import.meta.env.ATTEMPT_TIMESTAMP_SECRET);

const emailPool = [];
let currentEmailIndex = 0;

let i = 1;
while (true) {
  const address = import.meta.env[`GMAIL_ADDRESS_${i}`];
  const password = import.meta.env[`GMAIL_PASSWORD_${i}`];
  if (!address || !password) break;
  
  emailPool.push({
    address,
    password,
    index: i
  });
  i++;
}

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

    let current_time;
    let current_time_string;

    const client = await pool.connect();
    try {
      const profileQuery = `
        SELECT EXISTS(
          SELECT 1 FROM profiles 
          WHERE LOWER(email) = LOWER($1)
        ) as email_exists
      `;
      const profileResult = await client.query(profileQuery, [email]);
      
      if (profileResult.rows[0]?.email_exists) {
        return new Response(JSON.stringify({
          error: 'Email already registered',
          message: 'User with the same email has already registered. Please log in.'
        }), {
          status: 409,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      current_time = Math.floor(Date.now() / 1000);
      current_time_string = String(current_time);

      const { success } = await sendVerificationEmail(
        emailPool, 
        verification_secret,
        product_name, 
        email, 
        password,
        current_time_string, 
      );

      if (!success) {
        throw new Error('Failed to send verification email');
      }

    } finally {
      client.release();
    }

    return new Response(JSON.stringify({ 
      verificationURL: generateVerificationURL(
        email_secret, 
        email, 
        password_secret, 
        password, 
        timestamp_secret, 
        current_time_string, 
        attempt_timestamp_secret, 
        String(current_time - 10)
      )
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
