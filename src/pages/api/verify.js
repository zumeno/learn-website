export const prerender = false;
import { createClient } from "@supabase/supabase-js";
import { generateSecretKeyHash, generateCode, decryptCode, generateVerificationURL, decryptVerificationURL, generateVerificationCode } from "../../lib/generateCodes.js";

const verification_secret = generateSecretKeyHash(import.meta.env.VERIFICATION_SECRET);
const email_secret = generateSecretKeyHash(import.meta.env.EMAIL_SECRET);
const password_secret = generateSecretKeyHash(import.meta.env.PASSWORD_SECRET);
const timestamp_secret = generateSecretKeyHash(import.meta.env.TIMESTAMP_SECRET);
const attempt_timestamp_secret = generateSecretKeyHash(import.meta.env.ATTEMPT_TIMESTAMP_SECRET);

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
    const code = requestBody.code;
    const action = requestBody.action;

    if (!url) {
      return new Response(JSON.stringify({ 
        error: 'Missing URL',
        message: 'A valid URL is required to proceed with verification'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (!code) {
      return new Response(JSON.stringify({ 
        error: 'Missing Code',
        message: 'The verification code is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (!action) {
      return new Response(JSON.stringify({ 
        error: 'Missing Action',
        message: 'Action not specified.'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (!/^\d{6}$/.test(code)) {
      return new Response(JSON.stringify({ 
        error: 'Invalid Code Format',
        message: 'Verification code must be exactly 6 digits'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const userData = decryptVerificationURL(url, email_secret, password_secret, timestamp_secret, attempt_timestamp_secret);

    const email = userData.email;
    const password = userData.password;
    const timestamp = userData.timestamp;
    const attemptTimestamp = userData.attemptTimestamp;

    if (!userData) {
      return new Response(JSON.stringify({ 
        error: 'Invalid Verification URL',
        message: 'The verification URL is invalid or expired'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    let current_time = Math.floor(Date.now() / 1000);
    const current_time_string = String(current_time); 

    const timePassed = current_time - attemptTimestamp;
    const waitTime = 10; 
    const timeLeft = Math.ceil(waitTime - timePassed);
    
    if (timePassed < waitTime) {
      return new Response(JSON.stringify({ 
        error: 'verification_too_soon',
        message: `Please wait ${timeLeft} more second${timeLeft !== 1 ? 's' : ''} before attempting verification again`
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (code != generateVerificationCode(verification_secret, email, password, timestamp)) {
      return new Response(JSON.stringify({ 
        error: 'Invalid Verification Code',
        message: 'The verification code is incorrect',
        verificationURL: generateVerificationURL(email_secret, email, password_secret, password, timestamp_secret, timestamp, attempt_timestamp_secret, current_time_string)
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    current_time = Math.floor(Date.now() / 1000);
    if ((current_time - timestamp) > (3 * 60 * 1000)) {
      return new Response(JSON.stringify({ 
        error: 'Expired Verification Code',
        message: 'The verification code has expired'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const supabase = createClient(
      import.meta.env.SUPABASE_URL,
      import.meta.env.SUPABASE_SERVICE_ROLE_KEY
    );

    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("email")
      .eq("email", email)
      .maybeSingle();

    if (profileError) {
      return new Response(JSON.stringify({
        error: 'Profile lookup failed',
        message: profileError.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (profile && action === 'signup') {
      return new Response(JSON.stringify({
        message: 'User already registered. Please log in.'
      }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' }
      });
    } 

    let success_message;

    if (action === 'signup') {
      const { data: profiles, error: profileError } = await supabase
        .from('profiles')
        .insert({
          email: email,
          encrypted_password: new URL(url).searchParams.get('password')
        });

      success_message = 'Email verification successful! Redirecting to login...'
    } else if (action === 'reset') {
      const { data: profiles, error: profileError } = await supabase
        .from('profiles')
        .update({
          encrypted_password: new URL(url).searchParams.get('password')
        })
        .eq('email', email);

      success_message = 'Password reset successful! Redirecting to login...' 
    } else {
      return new Response(JSON.stringify({ 
        error: 'Invalid Action',
        message: 'Action must be either "signup" or "reset"'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({ 
      message: success_message,
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
      error: 'Registration failed',
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
