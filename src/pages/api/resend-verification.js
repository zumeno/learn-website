export const prerender = false;
import { createClient } from "@supabase/supabase-js";
import { generateSecretKeyHash, generateCode, generateVerificationURL, decryptCode, decryptVerificationURL } from "../../lib/generateCodes.js";
import { sendVerificationEmail } from "../../lib/sendVerificationEmail.js";

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
  const apiOrigin = `${requestUrl.protocol}//${requestUrl.host}`;
    
  if (origin && origin !== apiOrigin) {
    return new Response(JSON.stringify({ 
      error: 'Unauthorized origin',
      message: 'Requests must come from the same origin'
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
    
    const url = requestBody.url;

    if (!url) {
      return new Response(JSON.stringify({ 
        error: 'Missing URL',
        message: 'A valid URL is required to proceed with verification'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const userData = decryptVerificationURL(url, email_secret, password_secret, timestamp_secret, attempt_timestamp_secret)

    const email = userData.email;
    const password = userData.password;
    const timestamp = userData.timestamp;

    if (!userData) {
      return new Response(JSON.stringify({ 
        error: 'Invalid Verification URL',
        message: 'The current verification URL is invalid'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const current_time = Math.floor(Date.now() / 1000);
    const current_time_string = String(current_time); 

    const timePassed = current_time - timestamp;
    const waitTime = 60; 
    const timeLeft = Math.ceil(waitTime - timePassed);
    
    if (timePassed < waitTime) {
      return new Response(JSON.stringify({ 
        error: 'Verification URL is new',
        message: `Please wait ${timeLeft} more second${timeLeft !== 1 ? 's' : ''} before requesting a new verification email`
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const { success } = await sendVerificationEmail(
      emailPool, 
      verification_secret,
      product_name, 
      email,
      password,
      current_time_string 
    );

    if (!success) {
      throw new Error('Failed to send verification email');
    }

    return new Response(JSON.stringify({ 
      message: 'Verification code resent. Please check your email.',
      verificationURL: generateVerificationURL(email_secret, email, password_secret, password, timestamp_secret, current_time_string, attempt_timestamp_secret, String(current_time - 10)),
    }), {
      status: 200,
      headers: { 
        'Content-Type': 'application/json',
        ...(origin && { 'Access-Control-Allow-Origin': origin }),
        'Vary': 'Origin'
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    
    return new Response(JSON.stringify({ 
      error: 'Failed to send verification email',
      message: error.message,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
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
  const apiOrigin = `${requestUrl.protocol}//${requestUrl.host}`;
  
  const isAllowedOrigin = origin === apiOrigin;
  
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
