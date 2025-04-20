export const prerender = false;
import { createClient } from "@supabase/supabase-js";
import { generateSecretKeyHash, generateCode, decryptCode } from "../../lib/generateCodes.js";

const email_secret = generateSecretKeyHash(import.meta.env.EMAIL_SECRET);
const password_secret = generateSecretKeyHash(import.meta.env.PASSWORD_SECRET);

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

    if (!requestBody.email || !requestBody.password) {
      return new Response(JSON.stringify({ 
        error: 'Missing required fields',
        message: 'Both email and password are required'
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
      .select("email, encrypted_password") 
      .eq("email", requestBody.email)
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

    if (!profile) {
      return new Response(JSON.stringify({
        error: 'Authentication failed',
        message: 'No account found with this email address.'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const correctPassword = decryptCode(profile.encrypted_password, password_secret);

    if (requestBody.password != correctPassword) {
      return new Response(JSON.stringify({
        error: 'Authentication failed',
        message: 'Incorrect password. Please try again.'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({ 
      message: 'Login successful! Redirecting to dashboard...',
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
